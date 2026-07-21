"""오라클 ARM VM 재고 잡이 — GitHub Actions 상주 실행용.

한 워크플로우 실행이 최대 ~5.7시간 동안 60초마다 LaunchInstance 를 반복 호출한다.
재고 부족(500)/429/일시 401 은 재시도, 진짜 설정 오류(400)는 즉시 중단.
성공(또는 이미 인스턴스 존재) 시 디스코드로 알리고 종료 → 이후 실행은 중복 방지 가드로 no-op.
모든 설정은 환경변수(GitHub Secrets)로 주입 — 코드/로그에 비밀 미노출.
"""

import json
import os
import sys
import tempfile
import time
import urllib.request

import oci

INTERVAL = 60          # 초 (재고 대기 재시도 간격)
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
    """이미 살아있는 claude-bridge 인스턴스가 있으면 그 객체, 없으면 None(중복 생성 방지)."""
    dead = {"TERMINATED", "TERMINATING"}
    for inst in oci.pagination.list_call_get_all_results(
        cc.list_instances, compartment
    ).data:
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


def build_details(compartment):
    return oci.core.models.LaunchInstanceDetails(
        compartment_id=compartment,
        availability_domain=env("OCI_AD"),
        shape=SHAPE,
        display_name=DISPLAY,
        shape_config=oci.core.models.LaunchInstanceShapeConfigDetails(
            ocpus=OCPUS, memory_in_gbs=MEM_GB
        ),
        source_details=oci.core.models.InstanceSourceViaImageDetails(image_id=env("OCI_IMAGE")),
        create_vnic_details=oci.core.models.CreateVnicDetails(
            subnet_id=env("OCI_SUBNET"), assign_public_ip=True
        ),
        metadata={"ssh_authorized_keys": env("SSH_PUBKEY")},
    )


RETRY = {"InternalError", "TooManyRequests", "LimitExceeded", "NotAuthenticated"}


def is_retryable(e):
    if e.status in (429, 500, 401):
        return True
    msg = (e.message or "").lower()
    return "capacity" in msg or "out of host" in msg or e.code in RETRY


def main():
    compartment = env("OCI_COMPARTMENT")
    cfg, cc, net = build_clients()
    details = build_details(compartment)

    # 이미 있으면 알리고 끝(중복 생성 방지 — 앞선 실행이 이미 잡았을 수 있음)
    inst = existing_instance(cc, compartment)
    if inst is not None:
        print(f"already exists: {inst.id} ({inst.lifecycle_state})")
        return

    print(f"start grab loop — {SHAPE} {OCPUS}c/{MEM_GB}GB, {INTERVAL}s")
    start = time.monotonic()
    attempt = 0
    while (time.monotonic() - start) < MAX_MINUTES * 60:
        attempt += 1
        try:
            new = cc.launch_instance(details).data
            ip = public_ip_of(cc, net, compartment, new.id)
            print(f"SUCCESS attempt {attempt}: {new.id} ip={ip}")
            notify(
                "🎉 **오라클 VM 잡혔습니다!**\n"
                f"퍼블릭 IP: `{ip}` · {attempt}회째 (GitHub Actions)\n"
                "이제 SSH 접속·배포 준비 완료 — 세션에서 **오라클 됐어?** 하세요."
            )
            return
        except oci.exceptions.ServiceError as e:
            if is_retryable(e):
                if attempt % 10 == 1:
                    print(f"attempt {attempt}: waiting capacity ({e.status} {e.code})")
                time.sleep(BACKOFF_429 if e.status == 429 else INTERVAL)
            else:
                print(f"FATAL {e.status} {e.code}: {e.message}")
                notify(f"⛔ **오라클 재고 잡이 중단** — 설정 오류\n`{e.status} {e.code}: {e.message}`")
                sys.exit(1)
        except Exception as e:  # noqa: BLE001
            print(f"unexpected (continue): {type(e).__name__}: {e}")
            time.sleep(INTERVAL)
    print("time budget reached — next scheduled run will continue")


if __name__ == "__main__":
    main()
