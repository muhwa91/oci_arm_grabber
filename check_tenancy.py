"""구 오라클 테넌시 삭제 감시 — 삭제되는 순간을 디스코드로 알린다.

구 테넌시(도쿄)가 살아 있는 동안은 중복 계정 판정으로 새 계정(싱가포르) 가입이 막힌다.
그래서 하루 1회 테넌시를 조회해 **삭제 완료 시점만** 알린다.

판정: 조회 성공 = 아직 살아있음 · 404/NotAuthenticated 계열 = 삭제 완료
    · 그 외 예외(네트워크·타임아웃·429·5xx) = 판정 보류(삭제로 단정하지 않는다).
오탐(살아있는데 "삭제됐다"고 알림)이 최악이므로 삭제 판정은 RECHECK_SEC 뒤 재조회로 한 번 더 확인한다.
세 경우 모두 매일 디스코드로 알린다 — 알림이 **안 오는 것 자체가** 감시가 죽었다는 신호다
(시크릿 만료·워크플로 비활성화 등은 스크립트가 스스로 알릴 수 없다).
설정은 grab.py 와 같은 환경변수(GitHub Secrets)로 주입 — 코드/로그에 비밀 미노출.
"""

import sys
import time
from datetime import date, datetime, timedelta, timezone

import oci

# OCI config 구성·디스코드 전송을 레포 내 한 곳으로 유지(두 벌이 되면 한쪽만 낡는다).
# notify() 는 DISCORD_BOT_TOKEN·DISCORD_CHANNEL 로 보내고 DISCORD_USER_ID 멘션을 붙인다.
from grab import build_clients, notify

RECHECK_SEC = 30  # 삭제 판정 후 재확인 간격(일시 401 오탐 차단)
KST = timezone(timedelta(hours=9))  # 러너는 UTC — 카운트다운은 운영자님 기준 날짜로

# 삭제 요청 +30일 추정치일 뿐, 실제 삭제는 이보다 이르거나 늦을 수 있다(오라클 재량).
# 카운트다운은 참고용이고, 삭제 여부는 매일의 실제 조회 결과가 정한다.
DELETE_ETA = date(2026, 8, 27)

# 테넌시가 사라지면 서명 검증 자체가 실패해 401 NotAuthenticated, 리소스 조회는 404 로 온다.
DELETED_CODES = {"NotAuthenticated", "NotAuthorizedOrNotFound", "TenantNotFound"}

NEXT_STEPS = (
    "🚨 **구 오라클 테넌시가 삭제됐습니다** (도쿄) — 이제 새 계정 가입이 가능합니다.\n"
    "1. https://signup.oraclecloud.com — 홈 리전 **ap-singapore-1 (싱가포르)** 선택\n"
    "2. 가입 후 **PAYG 업그레이드**(Always Free 한도는 그대로)\n"
    "3. 사용자 API 키 발급 → 이 레포 Secrets 갱신"
    "(OCI_TENANCY·OCI_USER·OCI_FINGERPRINT·OCI_REGION·OCI_KEY_PEM·"
    "OCI_COMPARTMENT·OCI_AD·OCI_IMAGE·OCI_SUBNET)\n"
    "⚠️ 확인하셨으면 Actions 탭에서 **tenancy-watch 워크플로를 Disable** 하세요 — "
    "재가입 전까지 매일 같은 알림이 옵니다."
)


def verdict(status, code):
    """예외의 HTTP status·OCI code → 'deleted' | 'unknown'. (조회 성공은 호출부에서 'alive')"""
    return "deleted" if status == 404 or code in DELETED_CODES else "unknown"


def dday(today):
    """DELETE_ETA 까지 남은 일수 표기 — 'D-16' | 'D-DAY' | 'D+3'."""
    n = (DELETE_ETA - today).days
    if n > 0:
        return f"D-{n}"
    return "D-DAY" if n == 0 else f"D+{-n}"


def probe(cfg):
    """테넌시 1회 조회 → ('alive'|'deleted'|'unknown', 사유).

    사유는 알림에 실리므로 예외 message 원문은 넣지 않는다 — OCID 등이 섞여 나올 수 있다.
    (status·code 는 비밀을 담지 않고 원인 진단에 필요해 포함.) 테넌시 이름도 찍지 않는다.
    """
    try:
        tenancy = oci.identity.IdentityClient(cfg).get_tenancy(cfg["tenancy"]).data
    except oci.exceptions.ServiceError as e:
        kind = verdict(e.status, e.code)
        print(f"service error {e.status} {e.code} -> {kind}")
        return kind, f"ServiceError {e.status} {e.code}"
    except Exception as e:  # noqa: BLE001
        print(f"probe failed (undetermined): {type(e).__name__}: {e}")
        return "unknown", type(e).__name__
    if tenancy and tenancy.name:
        return "alive", ""
    return "unknown", "empty response"  # 200 인데 내용이 비면 살아있다고 단정하지 않는다


def selftest():
    assert dday(date(2026, 8, 11)) == "D-16"
    assert dday(DELETE_ETA) == "D-DAY"
    assert dday(date(2026, 8, 30)) == "D+3"
    assert verdict(404, "NotAuthorizedOrNotFound") == "deleted"
    assert verdict(401, "NotAuthenticated") == "deleted"
    assert verdict(404, "") == "deleted"
    assert verdict(429, "TooManyRequests") == "unknown"
    assert verdict(500, "InternalError") == "unknown"
    assert verdict(503, "ServiceUnavailable") == "unknown"
    print("selftest ok")


def main():
    if "--selftest" in sys.argv:  # OCI 호출 없이 판정 로직만 검증
        selftest()
        return
    cfg, _cc, _net = build_clients()  # grab.py 와 동일한 config(컴퓨트/네트워크 클라이언트는 미사용)
    state, why = probe(cfg)
    if state == "deleted":  # 오탐 방지 — 일시 401 이면 재조회에서 alive 로 돌아온다
        print(f"deleted? rechecking in {RECHECK_SEC}s")
        time.sleep(RECHECK_SEC)
        state, why = probe(cfg)
    tag = dday(datetime.now(KST).date())
    print(f"tenancy {state} ({tag}) {why}")
    if state == "deleted":
        notify(NEXT_STEPS)
    elif state == "alive":
        notify(f"🕒 구 테넌시 아직 살아있음 · 예상 삭제 {DELETE_ETA} ({tag})")
    else:  # 판정 보류 — 삭제로 오해하지 않게 문구를 분명히
        notify(
            f"⚠️ 구 테넌시 상태 확인 실패 — **판정 보류**(삭제된 것 아님) · "
            f"`{why}` · 예상 삭제 {DELETE_ETA} ({tag})"
        )


if __name__ == "__main__":
    main()
