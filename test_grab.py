"""grab.py 유닛 테스트 — 전부 hermetic(oci mock/fake). 라이브 OCI/launch 호출 없음.

단일 타겟(OCI_AD, FD 자동선택) 흐름의 에러 분류(rate/retry/fatal)·라운드별 existing
재확인(중복 방지·크래시 방지)·시간예산·OCI_AD 미설정 방어를 검증한다.
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
        "OCI_AD": "AD-1",
    }
)

import oci  # noqa: E402
import grab  # noqa: E402


def se(status, code, message):
    return oci.exceptions.ServiceError(status, code, {}, message)


# ---- classify: rate / retry / fatal ---------------------------------------
def test_classify():
    assert grab.classify(se(429, "TooManyRequests", "rate")) == "rate"
    assert grab.classify(se(500, "InternalError", "server")) == "retry"
    assert grab.classify(se(401, "NotAuthenticated", "token")) == "retry"
    assert grab.classify(se(500, "InternalError", "Out of host capacity.")) == "retry"
    for st in (500, 502, 503, 504):  # 전송계층 5xx 전반 → retry(성급중단 방지)
        assert grab.classify(se(st, "X", "transient")) == "retry", st
    # 진짜 설정오류 → fatal
    assert grab.classify(se(400, "InvalidParameter", "image ocid1.image not found")) == "fatal"
    assert grab.classify(se(404, "NotFound", "compartment does not exist")) == "fatal"
    print("ok classify")


# ---- main 루프 하네스 ------------------------------------------------------
class FakeCompute:
    def __init__(self, script, list_instances_raises=False):
        self.script = list(script)  # 각 원소: "OK" 또는 ServiceError 인스턴스
        self.calls = []  # launch 시도한 AD 기록
        self.list_instances_raises = list_instances_raises

    def launch_instance(self, details):
        self.calls.append(details.availability_domain)
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


def run_main(script, existing=None, sleep_cap=8, compute=None, real_existing=False):
    """main()을 fake 클라이언트로 구동. 반환: (compute, sleeps, notifications).

    real_existing=True 면 grab.existing_instance 를 mock하지 않고 실 함수 사용
    (FakeCompute.list_instances 를 태워 best-effort 예외삼킴을 end-to-end 검증).
    existing 은 값 또는 callable(라운드마다 호출) — 부분성공 후 재확인 시나리오용.
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
        "existing_instance": grab.existing_instance,
        "public_ip_of": grab.public_ip_of,
        "notify": grab.notify,
        "cumulative_minutes": grab.cumulative_minutes,
        "sleep": grab.time.sleep,
    }
    grab.build_clients = lambda: ({}, compute, object())
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
        grab.existing_instance = orig["existing_instance"]
        grab.public_ip_of = orig["public_ip_of"]
        grab.notify = orig["notify"]
        grab.cumulative_minutes = orig["cumulative_minutes"]
        grab.time.sleep = orig["sleep"]
    return compute, sleeps, notes


def test_success_first():
    compute, sleeps, notes = run_main(["OK"])
    assert compute.calls == ["AD-1"]  # 첫 시도 성공 후 즉시 종료
    assert sleeps == []
    assert any("잡혔습니다" in n and "1.2.3.4" in n for n in notes), notes
    print("ok success_first")


def test_retry_then_success_next_round():
    cap = se(500, "InternalError", "Out of host capacity.")
    compute, sleeps, notes = run_main([cap, "OK"])
    assert compute.calls == ["AD-1", "AD-1"]  # 라운드1 용량부족, 라운드2 성공
    assert sleeps == [grab.INTERVAL]  # 라운드 사이 평소 간격
    assert any("잡혔습니다" in n for n in notes)
    print("ok retry_then_success_next_round")


def test_5xx_retry_continues():
    # 503(일시장애) → fatal 아님, 다음 라운드 재시도 → 성공
    err = se(503, "ServiceUnavailable", "temporarily down")
    compute, sleeps, notes = run_main([err, "OK"])
    assert compute.calls == ["AD-1", "AD-1"]
    assert sleeps == [grab.INTERVAL]
    assert any("잡혔습니다" in n for n in notes)
    print("ok 5xx_retry_continues")


def test_429_backoff():
    rate = se(429, "TooManyRequests", "rate limited")
    compute, sleeps, notes = run_main([rate] * 8, sleep_cap=2)
    assert compute.calls == ["AD-1", "AD-1"]  # 매 라운드 1회 시도
    assert sleeps == [grab.BACKOFF_429, grab.BACKOFF_429], sleeps  # 429는 긴 백오프
    print("ok 429_backoff")


def test_fatal_exits():
    fatal = se(400, "InvalidParameter", "image ocid1.image not found")
    raised = False
    try:
        run_main([fatal, "OK"])
    except SystemExit as e:
        raised = True
        assert e.code == 1
    assert raised, "fatal은 sys.exit(1) 해야 한다"
    print("ok fatal_exits")


def test_existing_skips_loop():
    inst = types.SimpleNamespace(id="ocid1.instance.oc1..old", lifecycle_state="RUNNING")
    compute, sleeps, notes = run_main(["OK"], existing=inst)
    assert compute.calls == []  # 이미 있으면 launch 시도조차 안 함
    assert any("이미 확보됨" in n for n in notes)
    print("ok existing_skips_loop")


def test_partial_success_recheck_prevents_dup():
    # 부분성공(launch 클라 타임아웃) 후 라운드2 진입 전 existing 재확인 → 중복 launch 안 함
    inst = types.SimpleNamespace(id="ocid1.instance.oc1..made", lifecycle_state="PROVISIONING")
    state = {"n": 0}

    def existing_seq():
        state["n"] += 1
        return None if state["n"] == 1 else inst  # 라운드1 진입 시 없음, 라운드2 진입 시 있음

    compute, sleeps, notes = run_main(
        [TimeoutError("client timeout after server created")], existing=existing_seq
    )
    assert compute.calls == ["AD-1"], compute.calls  # 딱 1회만 launch (중복 없음)
    assert any("이미 확보됨" in n for n in notes), notes
    print("ok partial_success_recheck_prevents_dup")


def test_recheck_exception_does_not_kill_main():
    # 라운드별 existing 재확인(list_instances)이 일시 500을 던져도 main 크래시 없이
    # 다음 launch 로 진행해 성공까지 감. 실 existing_instance(best-effort 삼킴) 경로 사용.
    compute = FakeCompute(["OK"], list_instances_raises=True)
    compute, sleeps, notes = run_main(["OK"], compute=compute, real_existing=True)
    assert compute.calls == ["AD-1"], compute.calls  # 재확인 예외 삼키고 launch 진행
    assert any("잡혔습니다" in n for n in notes), notes
    print("ok recheck_exception_does_not_kill_main")


def test_time_budget_exit():
    # MAX_MINUTES 소진 시 launch 없이 정상 종료(다음 예약 실행이 이어받음)
    saved = grab.MAX_MINUTES
    grab.MAX_MINUTES = 0
    try:
        compute, sleeps, notes = run_main(["OK"])
        assert compute.calls == [], compute.calls  # 예산 0이면 루프 미진입
    finally:
        grab.MAX_MINUTES = saved
    print("ok time_budget_exit")


def test_oci_ad_missing_fatal():
    # OCI_AD 미설정 → 무음 no-op 대신 알림 후 fatal exit
    saved = os.environ.pop("OCI_AD")
    try:
        raised = False
        try:
            run_main(["OK"])
        except SystemExit as e:
            raised = True
            assert e.code == 1
        assert raised, "OCI_AD 미설정은 fatal exit 해야 한다"
    finally:
        os.environ["OCI_AD"] = saved
    print("ok oci_ad_missing_fatal")


if __name__ == "__main__":
    test_classify()
    test_success_first()
    test_retry_then_success_next_round()
    test_5xx_retry_continues()
    test_429_backoff()
    test_fatal_exits()
    test_existing_skips_loop()
    test_partial_success_recheck_prevents_dup()
    test_recheck_exception_does_not_kill_main()
    test_time_budget_exit()
    test_oci_ad_missing_fatal()
    print("\nALL PASS")
