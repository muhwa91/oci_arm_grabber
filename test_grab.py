"""grab.py 유닛 테스트 — 전부 hermetic(oci mock/fake). 라이브 OCI/launch 호출 없음.

순회 로직·조회 폴백·에러 분류(retry/skip/rate/fatal)·429 백오프·중복 방지를 검증한다.
실행: `python test_grab.py` (프레임워크 없음, assert 기반).
"""

import os
import sys
import types

# Windows cp949 콘솔에서 '—'/한글 print 가 UnicodeEncodeError로 죽는 것 방지(로컬 검증용, 프로덕션 무관).
try:
    sys.stdout.reconfigure(encoding="utf-8")
    sys.stderr.reconfigure(encoding="utf-8")
except (AttributeError, ValueError):
    pass

# grab 임포트 전에 main()이 읽는 env를 채워둔다(비밀 아님, 더미).
os.environ.update(
    {
        "OCI_COMPARTMENT": "ocid1.compartment.oc1..dummy",
        "OCI_TENANCY": "ocid1.tenancy.oc1..dummy",
        "OCI_IMAGE": "ocid1.image.oc1..dummy",
        "OCI_SUBNET": "ocid1.subnet.oc1..dummy",
        "SSH_PUBKEY": "ssh-ed25519 AAAA dummy",
        "OCI_AD": "FALLBACK-AD",
    }
)

import oci  # noqa: E402
import grab  # noqa: E402


def se(status, code, message):
    return oci.exceptions.ServiceError(status, code, {}, message)


# ---- classify: 4분류 -------------------------------------------------------
def test_classify():
    assert grab.classify(se(429, "TooManyRequests", "rate")) == "rate"
    assert grab.classify(se(500, "InternalError", "server")) == "retry"
    assert grab.classify(se(401, "NotAuthenticated", "token")) == "retry"
    assert grab.classify(se(500, "InternalError", "Out of host capacity.")) == "retry"
    # AD-specific subnet mismatch → skip
    assert (
        grab.classify(
            se(400, "InvalidParameter", "subnet ocid1.subnet is not in availability domain AD-2")
        )
        == "skip"
    )
    assert grab.classify(se(400, "InvalidParameter", "fault domain FD-3 invalid")) == "skip"
    # 조합 무관 설정오류 → fatal
    assert grab.classify(se(400, "InvalidParameter", "image ocid1.image not found")) == "fatal"
    assert grab.classify(se(404, "NotFound", "compartment does not exist")) == "fatal"
    # 5xx 전반은 retry (성급중단 방지)
    for st in (500, 502, 503, 504):
        assert grab.classify(se(st, "X", "transient")) == "retry", st
    # 좁힌 skip 힌트: 전역 오류("not available in this region")는 fatal, AD-명시만 skip
    assert (
        grab.classify(se(400, "InvalidParameter", "shape A1.Flex is not available in this region"))
        == "fatal"
    )
    assert (
        grab.classify(se(400, "InvalidParameter", "resource not available in availability domain AD-2"))
        == "skip"
    )
    print("ok classify")


def test_discover_empty_fd_gets_none():
    # FD data 가 빈 []여도 (예외 아님) → (ad, None) 으로 최소 1회 시도 확보
    idc = FakeIdentity(ads=["AD-1", "AD-2"], fds={"AD-1": ["FD-1"]})  # AD-2 FD 없음
    t = grab.discover_targets(idc, "ten", "comp")
    assert t == [("AD-1", "FD-1"), ("AD-2", None)], t
    print("ok discover_empty_fd_gets_none")


def test_discover_empty_ad_fallback():
    # AD 조회가 [] 반환(성공-빈응답) → targets 비면 OCI_AD 단일 폴백 (무음 no-op 방지)
    idc = FakeIdentity(ads=[])
    t = grab.discover_targets(idc, "ten", "comp")
    assert t == [("FALLBACK-AD", None)], t
    print("ok discover_empty_ad_fallback")


def test_discover_empty_no_ad_fatal():
    # 빈 응답 + OCI_AD 미설정 → fatal exit (5.7h 무음 낭비 대신 알림 후 중단)
    saved = os.environ.pop("OCI_AD")
    try:
        idc = FakeIdentity(ads=[])
        raised = False
        try:
            grab.discover_targets(idc, "ten", "comp")
        except SystemExit as e:
            raised = True
            assert e.code == 1
        assert raised, "빈 targets + OCI_AD 없음은 fatal exit 해야 한다"
    finally:
        os.environ["OCI_AD"] = saved
    print("ok discover_empty_no_ad_fatal")


# ---- discover_targets: 정상 · AD폴백 · FD폴백 ------------------------------
class FakeIdentity:
    def __init__(self, ads=None, fds=None, ad_raise=False, fd_raise_on=None):
        self._ads = ads or []
        self._fds = fds or {}
        self._ad_raise = ad_raise
        self._fd_raise_on = fd_raise_on or set()

    def list_availability_domains(self, compartment_id):
        if self._ad_raise:
            raise RuntimeError("boom AD")
        data = [types.SimpleNamespace(name=n) for n in self._ads]
        return types.SimpleNamespace(data=data)

    def list_fault_domains(self, compartment_id, availability_domain):
        if availability_domain in self._fd_raise_on:
            raise RuntimeError("boom FD")
        data = [types.SimpleNamespace(name=n) for n in self._fds.get(availability_domain, [])]
        return types.SimpleNamespace(data=data)


def test_discover_normal():
    idc = FakeIdentity(ads=["AD-1", "AD-2"], fds={"AD-1": ["FD-1", "FD-2"], "AD-2": ["FD-1"]})
    t = grab.discover_targets(idc, "ten", "comp")
    assert t == [("AD-1", "FD-1"), ("AD-1", "FD-2"), ("AD-2", "FD-1")], t
    print("ok discover_normal")


def test_discover_ad_fallback():
    idc = FakeIdentity(ad_raise=True, fds={"FALLBACK-AD": ["FD-1"]})
    t = grab.discover_targets(idc, "ten", "comp")
    assert t == [("FALLBACK-AD", "FD-1")], t  # OCI_AD 폴백
    print("ok discover_ad_fallback")


def test_discover_fd_fallback():
    idc = FakeIdentity(ads=["AD-1", "AD-2"], fds={"AD-1": ["FD-1"]}, fd_raise_on={"AD-2"})
    t = grab.discover_targets(idc, "ten", "comp")
    assert t == [("AD-1", "FD-1"), ("AD-2", None)], t  # AD-2는 FD 미지정(None)
    print("ok discover_fd_fallback")


# ---- main 루프: success / fatal / skip→success / 429 backoff / existing ----
class FakeCompute:
    def __init__(self, script, list_instances_raises=False):
        self.script = list(script)  # 각 원소: "OK" 또는 ServiceError 인스턴스
        self.calls = []  # (ad, fd) 시도 기록
        self.list_instances_raises = list_instances_raises

    def launch_instance(self, details):
        self.calls.append((details.availability_domain, details.fault_domain))
        item = self.script.pop(0)
        if item == "OK":
            return types.SimpleNamespace(data=types.SimpleNamespace(id="ocid1.instance.oc1..new"))
        raise item

    def list_instances(self, compartment, **kwargs):
        # 실 existing_instance(oci.pagination) 경로 테스트용 — 일시장애 시뮬레이션.
        if self.list_instances_raises:
            raise se(500, "InternalError", "list_instances transient")
        return types.SimpleNamespace(data=[], headers={})


class _Stop(Exception):
    pass


def run_main(monkey_targets, script, existing=None, sleep_cap=8, compute=None, real_existing=False):
    """main()을 fake 클라이언트로 구동. 반환: (compute, sleeps, notifications).

    real_existing=True 면 grab.existing_instance 를 mock하지 않고 실 함수 사용
    (FakeCompute.list_instances 를 태워 best-effort 예외삼킴을 end-to-end 검증).
    """
    if compute is None:
        compute = FakeCompute(script)
    sleeps, notes = [], []

    def fake_sleep(s):
        sleeps.append(s)
        if len(sleeps) >= sleep_cap:  # 무한 루프 방지(성공/fatal 없는 시나리오)
            raise _Stop()

    orig = {
        "build_clients": grab.build_clients,
        "discover_targets": grab.discover_targets,
        "existing_instance": grab.existing_instance,
        "public_ip_of": grab.public_ip_of,
        "notify": grab.notify,
        "cumulative_minutes": grab.cumulative_minutes,
        "sleep": grab.time.sleep,
    }
    grab.build_clients = lambda: ({}, object(), compute, object())
    grab.discover_targets = lambda *a, **k: monkey_targets
    if not real_existing:
        grab.existing_instance = (
            (lambda cc, comp: existing()) if callable(existing) else (lambda cc, comp: existing)
        )
    grab.public_ip_of = lambda *a, **k: "1.2.3.4"
    grab.notify = lambda m: notes.append(m)
    grab.cumulative_minutes = lambda: None
    grab.time.sleep = fake_sleep
    try:
        grab.main()
    except _Stop:
        pass
    finally:
        grab.build_clients = orig["build_clients"]
        grab.discover_targets = orig["discover_targets"]
        grab.existing_instance = orig["existing_instance"]
        grab.public_ip_of = orig["public_ip_of"]
        grab.notify = orig["notify"]
        grab.cumulative_minutes = orig["cumulative_minutes"]
        grab.time.sleep = orig["sleep"]
    return compute, sleeps, notes


def test_success_first():
    targets = [("AD-1", "FD-1"), ("AD-2", "FD-1")]
    compute, sleeps, notes = run_main(targets, ["OK"])
    assert compute.calls == [("AD-1", "FD-1")]  # 첫 조합에서 성공하고 즉시 종료
    assert sleeps == []
    assert any("잡혔습니다" in n and "1.2.3.4" in n for n in notes), notes
    print("ok success_first")


def test_skip_then_success():
    targets = [("AD-1", "FD-1"), ("AD-2", "FD-1")]
    skip_err = se(400, "InvalidParameter", "subnet is not in availability domain AD-1")
    compute, sleeps, notes = run_main(targets, [skip_err, "OK"])
    # AD-1 조합은 skip, AD-2에서 성공 — 전체 중단 없이 다음 AD로 넘어갔다
    assert compute.calls == [("AD-1", "FD-1"), ("AD-2", "FD-1")], compute.calls
    assert any("잡혔습니다" in n for n in notes)
    print("ok skip_then_success")


def test_retry_then_success_next_round():
    # 단일 조합, 첫 라운드 500(용량부족) → 다음 라운드 성공. 라운드 사이 INTERVAL 대기.
    targets = [("AD-1", "FD-1")]
    cap = se(500, "InternalError", "Out of host capacity.")
    compute, sleeps, notes = run_main(targets, [cap, "OK"])
    assert compute.calls == [("AD-1", "FD-1"), ("AD-1", "FD-1")]
    assert sleeps == [grab.INTERVAL]  # 라운드 사이 평소 간격 1회
    assert any("잡혔습니다" in n for n in notes)
    print("ok retry_then_success_next_round")


def test_429_backoff():
    targets = [("AD-1", "FD-1"), ("AD-2", "FD-1")]
    rate = se(429, "TooManyRequests", "rate limited")
    # 매 라운드 첫 조합에서 429 → 그 라운드 즉시 백오프, 두번째 조합은 시도 안 함
    compute, sleeps, notes = run_main(targets, [rate] * 8, sleep_cap=2)
    assert compute.calls == [("AD-1", "FD-1"), ("AD-1", "FD-1")], compute.calls
    assert sleeps == [grab.BACKOFF_429, grab.BACKOFF_429], sleeps
    print("ok 429_backoff")


def test_fatal_exits():
    targets = [("AD-1", "FD-1"), ("AD-2", "FD-1")]
    fatal = se(400, "InvalidParameter", "image ocid1.image not found")
    raised = False
    try:
        run_main(targets, [fatal, "OK"])
    except SystemExit as e:
        raised = True
        assert e.code == 1
    assert raised, "fatal은 sys.exit(1) 해야 한다"
    print("ok fatal_exits")


def test_existing_skips_loop():
    targets = [("AD-1", "FD-1")]
    inst = types.SimpleNamespace(id="ocid1.instance.oc1..old", lifecycle_state="RUNNING")
    compute, sleeps, notes = run_main(targets, ["OK"], existing=inst)
    assert compute.calls == []  # 이미 있으면 launch 시도조차 안 함
    print("ok existing_skips_loop")


def test_5xx_retry_continues():
    # 503(일시장애) → fatal 아님, retry로 다음 라운드 계속 → 성공
    targets = [("AD-1", "FD-1")]
    err = se(503, "ServiceUnavailable", "temporarily down")
    compute, sleeps, notes = run_main(targets, [err, "OK"])
    assert compute.calls == [("AD-1", "FD-1"), ("AD-1", "FD-1")]
    assert sleeps == [grab.INTERVAL]
    assert any("잡혔습니다" in n for n in notes)
    print("ok 5xx_retry_continues")


def test_partial_success_recheck_prevents_dup():
    # 부분성공(launch 클라 타임아웃) 후 라운드2 진입 전 existing 재확인 → 중복 launch 안 함
    targets = [("AD-1", "FD-1")]
    inst = types.SimpleNamespace(id="ocid1.instance.oc1..made", lifecycle_state="PROVISIONING")
    state = {"n": 0}

    def existing_seq():
        state["n"] += 1
        return None if state["n"] == 1 else inst  # 라운드1 진입 시 없음, 라운드2 진입 시 있음

    compute, sleeps, notes = run_main(
        targets, [TimeoutError("client timeout after server created")], existing=existing_seq
    )
    assert compute.calls == [("AD-1", "FD-1")], compute.calls  # 딱 1회만 launch (중복 없음)
    assert any("이미 확보됨" in n for n in notes), notes
    print("ok partial_success_recheck_prevents_dup")


def test_recheck_exception_does_not_kill_main():
    # 라운드별 existing 재확인(list_instances)이 일시 500을 던져도 main 크래시 없이
    # launch 순회를 계속해 성공까지 감. 실 existing_instance(best-effort 삼킴) 경로 사용.
    targets = [("AD-1", "FD-1")]
    compute = FakeCompute(["OK"], list_instances_raises=True)
    compute, sleeps, notes = run_main(targets, ["OK"], compute=compute, real_existing=True)
    assert compute.calls == [("AD-1", "FD-1")], compute.calls  # 재확인 예외 삼키고 launch 진행
    assert any("잡혔습니다" in n for n in notes), notes
    print("ok recheck_exception_does_not_kill_main")


def test_consecutive_skip_rounds_fatal():
    # 전 조합이 계속 skip → SKIP_ROUNDS_FATAL 라운드 후 fatal 승격(리전 오설정 무음 방지)
    targets = [("AD-1", "FD-1"), ("AD-2", "FD-1")]
    skip = se(400, "InvalidParameter", "subnet is not in availability domain")
    raised = False
    try:
        run_main(targets, [skip] * 12, sleep_cap=20)
    except SystemExit as e:
        raised = True
        assert e.code == 1
    assert raised, "연속 전조합 skip 은 fatal 승격해야 한다"
    print("ok consecutive_skip_rounds_fatal")


if __name__ == "__main__":
    test_classify()
    test_discover_normal()
    test_discover_ad_fallback()
    test_discover_fd_fallback()
    test_discover_empty_fd_gets_none()
    test_discover_empty_ad_fallback()
    test_discover_empty_no_ad_fatal()
    test_success_first()
    test_skip_then_success()
    test_retry_then_success_next_round()
    test_429_backoff()
    test_fatal_exits()
    test_existing_skips_loop()
    test_5xx_retry_continues()
    test_partial_success_recheck_prevents_dup()
    test_recheck_exception_does_not_kill_main()
    test_consecutive_skip_rounds_fatal()
    print("\nALL PASS")
