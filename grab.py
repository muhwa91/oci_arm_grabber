"""오라클 ARM VM 재고 잡이 — GitHub Actions 상주 실행용.

한 워크플로우 실행이 최대 ~5.7시간 동안 60초마다 단일 타겟(OCI_AD, FD는 OCI 자동선택)에
LaunchInstance 를 반복 호출한다. (계정 리전이 단일 AD라 AD×FD 순회는 재고 이득 없이
429만 유발 → 단일 타겟이 최선. 실측 확인.)
에러 분류: 용량부족(500)·전송 5xx·일시 401 → 다음 라운드 재시도 · 429 → 백오프
(계정 전역 레이트리밋) · 조합 무관 설정오류(잘못된 image/shape/compartment 등) → 즉시 중단.
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

INTERVAL = 45          # 초 (라운드 사이 재시도 간격 — 60→45 실험, 429 관찰 후 조정)
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
    """디스코드 전송 → 성공 True / 실패·미설정 False.

    실패해도 예외는 던지지 않는다(잡이 루프를 죽이면 안 된다). 다만 **결과를 돌려준다** —
    감시 스크립트(check_tenancy.py)는 이 값을 보고 종료코드를 정한다. 조용한 401 이
    "알림이 나갔다"로 둔갑하면 워크플로가 초록인데 아무도 못 받는 상태가 된다(2026-08-12 실사고).
    """
    token = env("DISCORD_BOT_TOKEN", required=False)
    channel = env("DISCORD_CHANNEL", required=False)
    if not token or not channel:
        # 문장부호는 ASCII 로 — cp949 콘솔(로컬 윈도우)에서 em dash 는 UnicodeEncodeError 다.
        print("::error::discord 미설정 (DISCORD_BOT_TOKEN/DISCORD_CHANNEL 없음)")
        return False
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
    return cfg, oci.core.ComputeClient(cfg), oci.core.VirtualNetworkClient(cfg)


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


def build_details(compartment, ad, image, subnet, pubkey):
    """단일 AD LaunchInstanceDetails. fault_domain 미지정(None) → OCI 자동선택."""
    return oci.core.models.LaunchInstanceDetails(
        compartment_id=compartment,
        availability_domain=ad,
        fault_domain=None,
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


def classify(e):
    """ServiceError → 'rate' | 'retry' | 'fatal'.

    rate  = 429 계정 전역 레이트리밋 → 다음 라운드 백오프(BACKOFF_429).
    retry = 500/전송5xx/일시401/용량부족 → 다음 라운드 재시도(INTERVAL).
    fatal = 진짜 설정오류(잘못된 image/shape/compartment 등) → 즉시 중단·알림.
    """
    if e.status == 429:
        return "rate"
    if e.status in (500, 502, 503, 504, 401):  # 전송계층 5xx 전반은 일시장애 → 재시도
        return "retry"
    msg = (e.message or "").lower()
    if "capacity" in msg or "out of host" in msg or e.code in RETRY:
        return "retry"
    return "fatal"


def maybe_notify_progress(start, attempt, last_slot):
    """벽시계 매시 정각(x:00)에 대기 진행 알림 1회. 다음 slot 값을 반환."""
    slot = int(time.time() // 3600)
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
    image = env("OCI_IMAGE")
    subnet = env("OCI_SUBNET")
    pubkey = env("SSH_PUBKEY")
    ad = env("OCI_AD", required=False)
    if not ad:  # 미설정 방어 — 무음 no-op 대신 디스코드 알림 후 중단
        notify("⛔ **오라클 재고 잡이 중단** — OCI_AD 미설정")
        print("FATAL: OCI_AD not set")
        sys.exit(1)
    _cfg, cc, net = build_clients()
    details = build_details(compartment, ad, image, subnet, pubkey)  # 고정 — 매 라운드 동일

    print(f"start grab loop — {SHAPE} {OCPUS}c/{MEM_GB}GB [{ad}], {INTERVAL}s")
    deadline = time.monotonic() + MAX_MINUTES * 60
    start = time.monotonic()
    last_slot = int(time.time() // 3600)  # 벽시계 60분 버킷(x:00 정각 정렬); 시작 직후 발신 방지
    attempt = 0
    while time.monotonic() < deadline:
        # 라운드마다 중복 재확인 — 부분성공(서버는 생성했으나 클라 타임아웃)·겹치는 예약 실행 차단
        inst = existing_instance(cc, compartment)
        if inst is not None:
            print(f"already exists: {inst.id} ({inst.lifecycle_state})")
            notify(f"✅ 오라클 VM 이미 확보됨 — `{inst.id}` ({inst.lifecycle_state})")
            return
        last_slot = maybe_notify_progress(start, attempt, last_slot)
        attempt += 1
        try:
            new = cc.launch_instance(details).data
            ip = public_ip_of(cc, net, compartment, new.id)
            print(f"SUCCESS attempt {attempt} [{ad}]: {new.id} ip={ip}")
            notify(
                "🎉 **오라클 VM 잡혔습니다!**\n"
                f"퍼블릭 IP: `{ip}` · {attempt}회째 [{ad}] (GitHub Actions)\n"
                "이제 SSH 접속·배포 준비 완료 — 세션에서 **오라클 됐어?** 하세요."
            )
            return
        except oci.exceptions.ServiceError as e:
            kind = classify(e)
            if kind == "fatal":  # 조합 무관 진짜 설정오류 → 중단
                print(f"FATAL {e.status} {e.code}: {e.message}")
                notify(f"⛔ **오라클 재고 잡이 중단** — 설정 오류\n`{e.status} {e.code}: {e.message}`")
                sys.exit(1)
            # rate/retry → 다음 라운드 재시도(429면 더 쉼)
            if attempt % 10 == 1:
                print(f"attempt {attempt} [{ad}]: waiting capacity ({e.status} {e.code})")
            time.sleep(BACKOFF_429 if kind == "rate" else INTERVAL)
        except Exception as e:  # noqa: BLE001
            print(f"unexpected (continue) [{ad}]: {type(e).__name__}: {e}")
            time.sleep(INTERVAL)
    print("time budget reached — next scheduled run will continue")


if __name__ == "__main__":
    main()
