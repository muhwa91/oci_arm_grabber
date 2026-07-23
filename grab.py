"""오라클 ARM VM 재고 잡이 — GitHub Actions 상주 실행용.

한 워크플로우 실행이 최대 ~5.7시간 동안, 계정의 **모든 AD × 모든 FD** 조합을
매 라운드 순차로 LaunchInstance 호출한다(ARM 무료 재고는 AD마다 따로 풀리므로
단일 AD만 두드리면 다른 AD 재고를 놓친다 — 확보 확률 최대화의 핵심).
에러 3분류: 용량부족(500)/일시 401 → 다음 조합 계속 · 429 → 그 라운드 백오프
(계정 전역 레이트리밋) · AD/FD-특정 구성불일치(subnet 미배치 등) → 그 조합만 skip ·
조합 무관 설정오류(잘못된 image/shape 등) → 즉시 중단.
성공(또는 이미 인스턴스 존재) 시 디스코드로 알리고 종료 → 이후 실행은 중복 방지 가드로 no-op.
모든 설정은 환경변수(GitHub Secrets)로 주입 — 코드/로그에 비밀 미노출.
"""

import json
import os
import sys
import tempfile
import time
import urllib.request
from datetime import datetime, timezone

import oci

INTERVAL = 60          # 초 (라운드 사이 재시도 간격)
PER_TARGET_GAP = 8     # 초 (같은 라운드 내 조합 간 간격 — 연속 타격발 429 완화; 짧게 둬 재고순간 놓침 최소화)
BACKOFF_429 = 120      # 429 발생 라운드는 더 쉼
MAX_MINUTES = 340      # 이 시간 넘으면 종료(다음 예약 실행이 이어받음; Actions 6h 한도 회피)
DISPLAY = "claude_bridge"
OCPUS = 1
MEM_GB = 6
SHAPE = "VM.Standard.A1.Flex"


def env(k, required=True):
    v = os.environ.get(k, "")
    if required and not v:
        print(f"::error::missing env {k}")
        sys.exit(1)
    return v


def notify(msg):
    token = env("DISCORD_BOT_TOKEN", required=False)
    channel = env("DISCORD_CHANNEL", required=False)
    if not token or not channel:
        return
    uid = env("DISCORD_USER_ID", required=False)
    content = (f"<@{uid}> " if uid else "") + msg
    body = json.dumps({"content": content}).encode()
    req = urllib.request.Request(
        f"https://discord.com/api/v10/channels/{channel}/messages",
        data=body,
        headers={
            "Authorization": f"Bot {token}",
            "Content-Type": "application/json",
            "User-Agent": "DiscordBot (https://github.com/muhwa91, 1.0)",
        },
        method="POST",
    )
    try:
        urllib.request.urlopen(req, timeout=15)
    except Exception as e:  # noqa: BLE001
        print(f"discord notify failed (ignored): {type(e).__name__}: {e}")


def cumulative_minutes():
    """브리지 `오라클` 명령과 동일 집계 — 이 워크플로우 전체의 누적 경과분(≈ 누적 시도수).

    GitHub API로 실행 목록 조회 → conclusion 이 cancelled 아닌 실행의 run_started_at
    최솟값 = 캠페인 시작 → now - 시작 = 누적. 60초 재시도라 시도수 ≈ 경과분.
    토큰/레포 없음·조회 실패는 None(호출부가 이번-실행 수치로 폴백).
    """
    repo = os.environ.get("GITHUB_REPOSITORY", "")
    token = os.environ.get("GITHUB_TOKEN", "")
    if not repo or not token:
        return None
    req = urllib.request.Request(
        f"https://api.github.com/repos/{repo}/actions/runs?per_page=100",
        headers={
            "Authorization": f"Bearer {token}",
            "User-Agent": "oci-arm-grabber (https://github.com/muhwa91)",
            "Accept": "application/vnd.github+json",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            runs = json.load(resp).get("workflow_runs", [])
    except Exception as e:  # noqa: BLE001
        print(f"cumulative fetch failed (fallback): {type(e).__name__}: {e}")
        return None
    starts = []
    for r in runs:
        if r.get("conclusion") == "cancelled":  # 테스트로 취소한 실행 제외(브리지와 동일)
            continue
        try:
            starts.append(datetime.fromisoformat(r["run_started_at"]))  # 3.11+ 'Z' 파싱
        except (KeyError, TypeError, ValueError):
            pass
    if not starts:
        return None
    return max(0, int((datetime.now(timezone.utc) - min(starts)).total_seconds())) // 60


def build_clients():
    key_path = os.path.join(tempfile.gettempdir(), "oci_api_key.pem")
    with open(key_path, "w", encoding="utf-8") as f:
        f.write(env("OCI_KEY_PEM"))
    os.chmod(key_path, 0o600)
    cfg = {
        "user": env("OCI_USER"),
        "tenancy": env("OCI_TENANCY"),
        "fingerprint": env("OCI_FINGERPRINT"),
        "region": env("OCI_REGION"),
        "key_file": key_path,
    }
    oci.config.validate_config(cfg)
    return (
        cfg,
        oci.identity.IdentityClient(cfg),
        oci.core.ComputeClient(cfg),
        oci.core.VirtualNetworkClient(cfg),
    )


def discover_targets(identity, tenancy, compartment):
    """계정의 모든 (AD, FD) 조합 목록을 반환 — 확보 확률 최대화의 핵심.

    반환: [(ad_name, fd_name), ...]. fd_name=None 이면 OCI 자동선택.
    조회 실패는 폴백(견고성): AD 조회 실패 → env OCI_AD 단일 · 특정 AD의 FD 조회
    실패 → 그 AD는 FD 미지정(None). (list_fault_domains 는 SDK상 IdentityClient 소속.)
    """
    try:
        ads = [ad.name for ad in identity.list_availability_domains(tenancy).data]
    except Exception as e:  # noqa: BLE001
        print(f"AD discovery failed, fallback to OCI_AD: {type(e).__name__}: {e}")
        ads = [env("OCI_AD")]
    targets = []
    for ad in ads:
        try:
            fds = [fd.name for fd in identity.list_fault_domains(compartment, ad).data]
        except Exception as e:  # noqa: BLE001
            print(f"FD discovery failed for {ad}, OCI auto-select: {type(e).__name__}: {e}")
            fds = [None]
        if not fds:  # "성공했지만 빈 data" 도 예외와 동일 취급 — 최소 1회는 OCI 자동선택으로 시도
            fds = [None]
        for fd in fds:
            targets.append((ad, fd))
    if not targets:  # AD 조회가 [] 반환 등 → 무음 no-op(5.7h 낭비) 방지
        ad = env("OCI_AD", required=False)
        if ad:
            print("no targets discovered, fallback to OCI_AD single")
            return [(ad, None)]
        notify("⛔ **오라클 재고 잡이 중단** — AD/FD 조회 결과 없고 OCI_AD 미설정")
        print("FATAL: no AD/FD discovered and no OCI_AD fallback")
        sys.exit(1)
    return targets


def existing_instance(cc, compartment):
    """이미 살아있는 claude-bridge 인스턴스가 있으면 그 객체, 없으면 None(중복 생성 방지).

    best-effort: list_instances 가 일시 500/429/타임아웃을 던져도 예외를 삼키고 None 반환
    (매 라운드 호출되는 안전망이므로 실행을 죽이면 안 됨). 조회 실패 라운드는 재확인 skip 효과.
    """
    dead = {"TERMINATED", "TERMINATING"}
    try:
        instances = oci.pagination.list_call_get_all_results(cc.list_instances, compartment).data
    except Exception as e:  # noqa: BLE001
        print(f"existing check failed (best-effort skip): {type(e).__name__}: {e}")
        return None
    for inst in instances:
        if inst.display_name == DISPLAY and inst.lifecycle_state not in dead:
            return inst
    return None


def public_ip_of(cc, net, compartment, instance_id):
    for _ in range(20):
        time.sleep(6)
        try:
            vas = cc.list_vnic_attachments(compartment, instance_id=instance_id).data
            if vas and vas[0].vnic_id:
                ip = net.get_vnic(vas[0].vnic_id).data.public_ip
                if ip:
                    return ip
        except oci.exceptions.ServiceError:
            pass
    return None


def build_details(compartment, ad, fd, image, subnet, pubkey):
    """(AD, FD) 지정 LaunchInstanceDetails. fd=None 이면 fault_domain 미지정 → OCI 자동선택."""
    return oci.core.models.LaunchInstanceDetails(
        compartment_id=compartment,
        availability_domain=ad,
        fault_domain=fd,
        shape=SHAPE,
        display_name=DISPLAY,
        shape_config=oci.core.models.LaunchInstanceShapeConfigDetails(
            ocpus=OCPUS, memory_in_gbs=MEM_GB
        ),
        source_details=oci.core.models.InstanceSourceViaImageDetails(image_id=image),
        create_vnic_details=oci.core.models.CreateVnicDetails(
            subnet_id=subnet, assign_public_ip=True
        ),
        metadata={"ssh_authorized_keys": pubkey},
    )


RETRY = {"InternalError", "TooManyRequests", "LimitExceeded", "NotAuthenticated"}
# ponytail: skip 은 AD/FD를 명시하는 문구로만 좁힌다 — "shape not available in this region" 같은
#           조합무관 전역오류를 skip으로 오분류하면 전 조합 무한 skip(무음 낭비)이 됨.
#           안전망: main 이 연속 SKIP_ROUNDS_FATAL 라운드 전조합 skip이면 fatal 승격.
SKIP_HINTS = (
    "not in availability domain",           # subnet AD-specific 미배치
    "not available in availability domain",  # 리소스가 그 AD에만 없음
    "not in this ad",
    "fault domain",                          # FD 지정 불일치(FD는 AD 내 지역성)
)
SKIP_ROUNDS_FATAL = 2  # 이만큼 연속으로 전 조합이 skip이면 리전 오설정으로 보고 중단


def classify(e):
    """ServiceError → 'rate' | 'retry' | 'skip' | 'fatal'.

    rate  = 429 계정 전역 레이트리밋 → 그 라운드 백오프.
    retry = 500/일시401/용량부족 → 다음 조합으로 계속(용량은 AD마다 다르므로 즉시 다음 AD).
    skip  = 특정 AD/FD에서만 나는 구성불일치(subnet AD-specific 등) → 그 조합만 건너뜀.
    fatal = 조합 무관 진짜 설정오류(잘못된 image/shape/compartment 등) → 즉시 중단·알림.
    """
    if e.status == 429:
        return "rate"
    if e.status in (500, 502, 503, 504, 401):  # 전송계층 5xx 전반은 일시장애 → 재시도
        return "retry"
    msg = (e.message or "").lower()
    if "capacity" in msg or "out of host" in msg or e.code in RETRY:
        return "retry"
    if any(h in msg for h in SKIP_HINTS):
        return "skip"
    return "fatal"


def maybe_notify_progress(start, attempt, last_slot):
    """벽시계 x:00 / x:30 정각에 대기 진행 알림 1회. 다음 slot 값을 반환."""
    slot = int(time.time() // 1800)
    if slot == last_slot:
        return last_slot
    cum = cumulative_minutes()  # 브리지 `오라클`과 동일 누적 집계
    if cum is not None:
        notify(
            f"⏳ 오라클 재고 대기 중 — 누적 약 {cum}회 시도 · "
            f"{cum // 60}시간 {cum % 60}분째"
        )
    else:  # 조회 실패 폴백 — 이번 실행 수치라도 알림은 나간다
        mins = int((time.monotonic() - start) // 60)
        notify(
            f"⏳ 오라클 재고 대기 중 — 이번 실행 {attempt}회 시도 · "
            f"{mins // 60}시간 {mins % 60}분째 (누적은 '오라클' 명령으로 확인)"
        )
    return slot


def main():
    compartment = env("OCI_COMPARTMENT")
    tenancy = env("OCI_TENANCY")
    image = env("OCI_IMAGE")
    subnet = env("OCI_SUBNET")
    pubkey = env("SSH_PUBKEY")
    _cfg, identity, cc, net = build_clients()
    targets = discover_targets(identity, tenancy, compartment)
    print(
        f"start grab loop — {SHAPE} {OCPUS}c/{MEM_GB}GB · "
        f"{len(targets)} AD/FD combos: {targets}"
    )
    deadline = time.monotonic() + MAX_MINUTES * 60
    start = time.monotonic()
    last_slot = int(time.time() // 1800)  # 벽시계 30분 버킷(x:00/x:30 정각 정렬); 시작 직후 발신 방지
    attempt = 0
    skip_rounds = 0  # 연속으로 전 조합이 skip 인 라운드 수(전역 오설정 감지용)
    while time.monotonic() < deadline:
        # 라운드마다 중복 재확인 — 부분성공(서버는 생성했으나 클라 타임아웃)·겹치는 예약 실행 차단
        inst = existing_instance(cc, compartment)
        if inst is not None:
            print(f"already exists: {inst.id} ({inst.lifecycle_state})")
            notify(f"✅ 오라클 VM 이미 확보됨 — `{inst.id}` ({inst.lifecycle_state})")
            return
        last_slot = maybe_notify_progress(start, attempt, last_slot)
        rate_limited = False  # 429 발생 시 이 라운드 백오프
        saw_non_skip = False  # 이 라운드에 skip 아닌 시도(retry/rate)가 하나라도 있었나
        did_attempt = False
        # 매 라운드: 모든 (AD, FD) 조합을 순차 시도 — 어느 AD든 순간 재고가 뜨면 잡는다
        for i, (ad, fd) in enumerate(targets):
            if time.monotonic() >= deadline:
                break
            if i > 0:  # 조합 사이 짧은 간격 — 연속 타격발 429 완화(첫 조합·라운드끝엔 없음, 이중대기 방지)
                time.sleep(PER_TARGET_GAP)
            attempt += 1
            did_attempt = True
            details = build_details(compartment, ad, fd, image, subnet, pubkey)
            try:
                new = cc.launch_instance(details).data
                ip = public_ip_of(cc, net, compartment, new.id)
                print(f"SUCCESS attempt {attempt} [{ad}/{fd}]: {new.id} ip={ip}")
                notify(
                    "🎉 **오라클 VM 잡혔습니다!**\n"
                    f"퍼블릭 IP: `{ip}` · {attempt}회째 [{ad}] (GitHub Actions)\n"
                    "이제 SSH 접속·배포 준비 완료 — 세션에서 **오라클 됐어?** 하세요."
                )
                return
            except oci.exceptions.ServiceError as e:
                kind = classify(e)
                if kind == "rate":
                    print(f"attempt {attempt} [{ad}/{fd}]: 429 rate limit → round backoff")
                    rate_limited = True
                    saw_non_skip = True
                    break  # 계정 전역 레이트리밋 → 이 라운드 중단하고 쉼
                if kind == "skip":
                    print(f"skip [{ad}/{fd}]: {e.status} {e.code}: {e.message}")
                    continue  # 그 조합만 건너뛰고 다른 AD 계속
                if kind == "retry":
                    saw_non_skip = True
                    if attempt % 20 == 1:
                        print(f"attempt {attempt} [{ad}/{fd}]: waiting capacity ({e.status} {e.code})")
                    continue  # 용량부족 → 즉시 다음 조합(다른 AD에 재고 있을 수 있음)
                # fatal: 조합 무관 설정오류 → 중단
                print(f"FATAL {e.status} {e.code}: {e.message}")
                notify(f"⛔ **오라클 재고 잡이 중단** — 설정 오류\n`{e.status} {e.code}: {e.message}`")
                sys.exit(1)
            except Exception as e:  # noqa: BLE001
                print(f"unexpected (continue) [{ad}/{fd}]: {type(e).__name__}: {e}")
                saw_non_skip = True
                continue
        # 전 조합이 skip 뿐이었던 라운드 누적 → 전역 오설정(리전/샤프)으로 보고 중단
        if did_attempt and not saw_non_skip:
            skip_rounds += 1
            if skip_rounds >= SKIP_ROUNDS_FATAL:
                print(f"FATAL: {skip_rounds} rounds all skipped — likely region/config error")
                notify("⛔ **오라클 재고 잡이 중단** — 모든 AD/FD 조합이 계속 skip(리전/구성 오설정 의심)")
                sys.exit(1)
        else:
            skip_rounds = 0
        # 라운드 완료 — 429면 더 쉬고, 아니면 평소 간격 대기 후 전 조합 재순회
        time.sleep(BACKOFF_429 if rate_limited else INTERVAL)
    print("time budget reached — next scheduled run will continue")


if __name__ == "__main__":
    main()
