"""구 오라클 테넌시 삭제 감시 — 삭제되는 순간을 텔레그램(감시 봇)으로 알린다.

구 테넌시(도쿄)가 살아 있는 동안은 중복 계정 판정으로 새 계정(싱가포르) 가입이 막힌다.
그래서 하루 1회 테넌시를 조회해 상태를 알린다(생존·보류·삭제 **세 경우 모두** 발신).
⚠️ 폰으로 나가는 문구는 «테넌시» 대신 **«오라클 계정»** 을 쓴다(2026-08-16 운영자 확정).
코드·주석의 «테넌시» 는 OCI 기술 용어라 그대로 둔다 — 바꿔야 하는 것은 발신 문구뿐이다.

판정: 조회 성공 = 아직 살아있음 · 404 계열 = 삭제 완료
    · 그 외 예외(401 인증실패·네트워크·타임아웃·429·5xx) = 판정 보류(삭제로 단정하지 않는다).
오탐(살아있는데 "삭제됐다"고 알림)이 최악이므로 삭제 판정은 RECHECK_SEC 뒤 재조회로 한 번 더 확인한다.
세 경우 모두 매일 텔레그램으로 알리고, **전송이 실패하면 종료코드 1 로 워크플로를 붉게** 만든다 —
알림이 안 오는 것을 사람이 매일 알아채는 데 기댔더니 실제로 놓쳤다(2026-08-12: 조용한 401).
⚠️ **디스코드 발송은 2026-08-16 운영자 지시로 제거됐다** — 종전엔 매일 오는 생존·보류를 디스코드가
맡고 텔레그램은 삭제 1회만 받았다. 이제 감시 봇이 **유일한 행선지**이므로, 매일 오는 🕒 생존 보고가
«감시가 살아 있다»는 확인선을 겸한다. 소음이라고 그 한 줄을 끄면 침묵과 고장을 구분할 수 없어진다.
설정은 grab.py 와 같은 환경변수(GitHub Secrets)로 주입 — 코드/로그에 비밀 미노출.
"""

import contextlib
import io
import json
import os
import re
import sys
import time
import urllib.request
from datetime import date, datetime, timedelta, timezone

import oci

# OCI config 구성·디스코드 전송을 레포 내 한 곳으로 유지(두 벌이 되면 한쪽만 낡는다).
# ⚠️ notify()(디스코드)는 이 파일에서 **더 이상 발송에 쓰지 않는다** — 2026-08-16 운영자 지시로
# 오라클 알림은 **텔레그램 감시 봇 전용**이 됐다(세 상태 전부 tg()).
# 그래도 import 는 남긴다 — 다만 **이유를 정확히 적는다(2026-08-16 점검 정정)**:
#   `grab.py` 의 notify() 호출 6곳은 **전부 반환값을 버린다.** 반환값 계약의 유일한 소비자는
#   방금 지운 이 파일의 main() 이었다 → **지금 그 계약을 쓰는 코드는 없다.**
#   notify_selftest() 는 «현재 소비자»를 지키는 게 아니라, 2026-08-12 회귀(docstring 은
#   True/False 인데 본문이 None 을 돌려줘 전송 성공에도 워크플로가 죽었다)의 **재발 방어**로만 남긴다.
#   test_grab.py 는 notify 를 몽키패치해서 그걸 못 잡는다. 지우지 마라.
# ⚠️ 이 단언이 자동 실행되는 유일 경로는 tenancy-watch.yml 의 --selftest 스텝인데,
#   삭제 감지 시 절차 4번이 **그 워크플로 Disable** 이다 → 그날로 방어가 멈춘다.
#   재가입 때 grab.yml 에 셀프테스트 스텝을 넣거나 test_grab.py 로 이관할 것.
from grab import build_clients, notify

RECHECK_SEC = 30  # 삭제 판정 후 재확인 간격(일시적 404 오탐 차단)
KST = timezone(timedelta(hours=9))  # 러너는 UTC — 카운트다운은 운영자 기준 날짜(KST)로

# 삭제 요청 +30일 추정치일 뿐, 실제 삭제는 이보다 이르거나 늦을 수 있다(오라클 재량).
# 카운트다운은 참고용이고, 삭제 여부는 매일의 실제 조회 결과가 정한다.
DELETE_ETA = date(2026, 8, 27)
ETA_STR = DELETE_ETA.strftime("%y-%m-%d")  # 폰 알림 미리보기에서 잘리지 않게 2자리 연도

# 401 NotAuthenticated 는 **일부러 뺐다**(2026-08-12). 테넌시 소멸도 401 을 내지만, API 키 회전·
# OCI_KEY_PEM 시크릿 손상·사용자 삭제·러너 클럭 스큐도 전부 401 이다 — 훨씬 흔하다. 게다가
# RECHECK_SEC 재조회는 **같은 cfg·같은 키로 같은 경로**를 타므로 지속적 자격증명 실패를 걸러내지
# 못한다(두 번 다 401 → 삭제 확정 → 오발신). 그 알림을 받으면 운영자가 싱가포르 재가입을 시도했다가
# 살아있는 구 테넌시 때문에 거절당한다 — 이 감시에서 오탐이 최악이다.
# 대가는 미탐(실제 삭제가 401 로만 나타나면 며칠 늦게 안다)이고, 그건 훨씬 싸다:
# 매일 오는 알림이 "판정 보류"로 바뀌므로 며칠 이어지면 눈에 띈다.
DELETED_CODES = {"NotAuthorizedOrNotFound", "TenantNotFound"}

PROJECT = "💼 oci_arm_grabber"  # 💼 는 폰으로 오는 알림 3종(발송이상·테넌시·PC활성화) 공통 표식


# 재가입 절차 — 알림 본문에서 뺐으므로 여기가 유일한 기록이다(2026-08-12).
#   1. https://signup.oraclecloud.com — 홈 리전 ap-singapore-1(싱가포르) 선택
#   2. 가입 후 PAYG 업그레이드(Always Free 한도는 그대로)
#   3. 사용자 API 키 발급 → 이 레포 Secrets 갱신
#      (OCI_TENANCY·OCI_USER·OCI_FINGERPRINT·OCI_REGION·OCI_KEY_PEM·
#       OCI_COMPARTMENT·OCI_AD·OCI_IMAGE·OCI_SUBNET)
#      🔴 PEM 은 **반드시 파일 리다이렉트**로 넣는다 — 인라인 금지(셸 히스토리·세션 로그에
#         개인키 전문이 평문으로 남고, 그 키는 테넌시 전체 API 권한이다):
#             gh secret set OCI_KEY_PEM --repo muhwa91/oci_arm_grabber < ~/oci_api_key.pem
#         등록 후 로컬 키 파일은 즉시 삭제한다.
#   4. Actions 탭에서 tenancy-watch 를 Disable — 안 하면 매일 같은 알림이 온다
#      ⚠️ Disable 하면 위 notify_selftest() 단언과 **감시 봇 생존 신호(🕒)가 함께 멈춘다.**
#         그 전에 grab.yml 로 셀프테스트를 옮기고, 생존 확인은 etf-info 의 getMe 스텝이 잇는다.


def kdate(d):
    """머리글 날짜 `26년 8월 27일`. strftime 의 `%-m`(리눅스 전용)을 피해 직접 조립한다."""
    return f"{d.year % 100}년 {d.month}월 {d.day}일"


def next_steps(today):
    """삭제 확인 알림 — 폰에서 네 줄로 끝난다.

    상세 절차를 싣지 않는 것은 의도다: 이 메시지를 Claude 에게 그대로 던지면 워크플로
    Disable·Secrets 갱신까지 처리하는 규약이라(2026-08-12 운영자 지시), 본문에 있어야 할
    것은 "무엇이 일어났고 다음이 무엇인가" 뿐이다. 절차는 위 주석이 보관한다.
    """
    return "\n".join(
        [f"[{kdate(today)}]", PROJECT, "🚨 오라클 계정 삭제완료", "- 새 계정 가입 필요"]
    )


def status_msg(state, why, today, tag):
    """상태 → 폰으로 나갈 문구. 순수(부작용 없음) — selftest 가 전문을 고정한다.

    ⚠️ **main() 안에 인라인으로 되돌리지 마라(2026-08-16 점검 지적).** 종전엔 alive·보류 문구가
    main() 안에 있어 selftest 가 한 줄도 검증하지 못했고, 그래서 «한 줄로 붙이지 마라» 같은
    형식 규칙이 주석의 부탁으로만 남았다. 여기 있으면 단언이 집행한다.
    마크다운 기호는 tg() 안의 to_plain() 이 벗긴다 — 문구에 남겨도 폰에는 평문으로 간다.
    """
    if state == "deleted":
        return next_steps(today)
    if state == "alive":
        # 문구·줄바꿈은 2026-08-16 운영자가 폰에서 받아 보고 확정한 형태다. 한 줄로 붙이지 마라.
        return f"🕒 오라클 계정 존재\n\n예상 삭제 {ETA_STR}({tag})"
    # 판정 보류 — 삭제로 오해하지 않게 문구를 분명히
    return (
        f"⚠️ 오라클 계정 상태 확인 실패 — **판정 보류**(삭제된 것 아님, "
        f"자격증명 문제일 수 있음) · `{why}` · 예상 삭제 {ETA_STR}({tag})"
    )


# `\s` 를 쓰면 개행까지 먹어 '-#\n다음 줄' 이 한 줄로 합쳐진다 → 같은 줄의 공백만([ \t]).
_MD = re.compile(r"\*\*|`|^-#[ \t]*", re.M)  # 디스코드 전용 마크업(굵게·코드·서브텍스트)


def to_plain(text):
    """디스코드 문구 → 텔레그램용 순수 텍스트.

    텔레그램은 parse_mode 없이 보내므로(마크다운 파싱 실패로 전송이 통째로 거절되는 걸 피한다)
    `**굵게**`·`` `코드` ``·`-# 서브텍스트`·`<링크>`(임베드 억제 표기)가 기호째 노출된다. 그것만 벗긴다.
    """
    return _MD.sub("", re.sub(r"<(https?://[^>\s]+)>", r"\1", text))


def mask(text, secret):
    """예외 메시지에서 시크릿을 가린다(이 레포는 PUBLIC — Actions 로그가 공개된다).

    원문뿐 아니라 **repr 로 escape 된 형태**도 지운다: 토큰에 개행이 섞이면(시크릿 붙여넣기 사고)
    http.client 가 InvalidURL 로 selector 를 repr 로 찍어 개행이 `\\n` 두 글자가 된다 —
    원문만 replace 하면 한 글자도 안 가려진다(실측).
    """
    if not secret:  # replace("", ...) 는 글자 사이마다 끼워 넣어 문자열을 망가뜨린다
        return text
    return text.replace(secret, "***").replace(repr(secret)[1:-1], "***")


# 쌍둥이: etf-info 레포의 check_morning_send.py 의 tg()/to_plain()/mask()
# — 한쪽만 고치지 마라(레포가 갈려 있어 공유 모듈은 못 만든다)
def tg(msg):
    """텔레그램 전송(수신 전용 봇). 실패는 삼키되 로그를 남긴다 — 조용한 실패는 감시가 없는 것과 같다.

    2026-08-16 부터 **유일한 발신 경로**다(디스코드 notify() 제거). 실패하면 알림이 통째로
    사라지므로 main() 이 종료코드 1 로 러너를 붉게 만든다.
    """
    token = os.environ.get("TELEGRAM_DEV_BOT_TOKEN", "")
    chat = os.environ.get("TELEGRAM_DEV_CHAT_ID", "")
    if not token or not chat:
        print("telegram skipped: 미설정")
        return False
    req = urllib.request.Request(
        f"https://api.telegram.org/bot{token}/sendMessage",
        # UTF-8 명시 필수 — 로케일이 cp949 인 환경에서 'strings must be encoded in UTF-8' 로 거절된다.
        data=json.dumps({"chat_id": chat, "text": to_plain(msg)}).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        urllib.request.urlopen(req, timeout=15)
        return True
    except Exception as e:  # noqa: BLE001
        # 토큰이 URL 경로에 들어가므로 예외 메시지에 평문으로 실린다 → 반드시 가리고 찍는다.
        print(f"telegram notify failed: {type(e).__name__}: {mask(str(e), token)}")
        return False


def verdict(status, code):
    """예외의 HTTP status·OCI code → 'deleted' | 'unknown'. (조회 성공은 호출부에서 'alive')

    401 은 'unknown' 이다 — 이유는 DELETED_CODES 주석 참조(오탐 회피, 미탐은 감수).
    """
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


def tg_selftest():
    """tg() 검증 — urlopen 을 갈아끼워 **실제로 만들어지는 Request** 를 본다(네트워크 안 나감).

    이 함수는 2026-08-12 신설이고, 같은 날 cp949 인코딩으로 텔레그램이 전송을 통째로 거절한
    사고가 있었다. 그 재발을 잡는 장치가 selftest 에 한 줄도 없었다.
    """
    seen = {}

    def fake_urlopen(req, **_kw):  # timeout 등은 안 본다
        seen["req"] = req
        return io.BytesIO(b'{"ok":true}')  # 반환값은 tg 가 쓰지 않는다

    saved = {k: os.environ.get(k) for k in ("TELEGRAM_DEV_BOT_TOKEN", "TELEGRAM_DEV_CHAT_ID")}
    real_urlopen = urllib.request.urlopen
    try:
        os.environ["TELEGRAM_DEV_BOT_TOKEN"] = "12345:ABCdef"
        os.environ["TELEGRAM_DEV_CHAT_ID"] = "42"
        urllib.request.urlopen = fake_urlopen
        assert tg("**굵게** 한글 메시지") is True
        # ① 본문이 UTF-8 로 디코드된다 — cp949 로 인코딩됐다면 여기서 깨진다.
        payload = json.loads(seen["req"].data.decode("utf-8"))
        assert payload["text"] == "굵게 한글 메시지", payload  # 한글 왕복 무손실 + 마크업 제거
        assert payload["chat_id"] == "42", payload

        # ② 시크릿 미설정이면 urlopen 을 아예 호출하지 않고 False.
        seen.clear()
        del os.environ["TELEGRAM_DEV_BOT_TOKEN"]
        assert tg("x") is False and not seen

        # ③ 예외가 나도 삼키고 False(러너를 죽이지 않는다) + 토큰이 로그에 안 남는다.
        #    개행 섞인 토큰 = 시크릿 붙여넣기 사고의 전형 → 실제 urlopen 이 InvalidURL 로 죽는다
        #    (URL 검증 단계라 소켓은 열리지 않는다). 이 레포는 PUBLIC 이라 로그가 공개된다.
        os.environ["TELEGRAM_DEV_BOT_TOKEN"] = "12345:ABCdef_SECRET\nX"
        urllib.request.urlopen = real_urlopen
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            assert tg("x") is False
        out = buf.getvalue()
        assert "InvalidURL" in out and "SECRET" not in out and "***" in out, out
    finally:
        urllib.request.urlopen = real_urlopen
        for k, v in saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v


def notify_selftest():
    """notify() 가 **bool 을 실제로 돌려주는지** 본다.

    2026-08-12 실사고: docstring 에 "성공 True / 실패 False" 라고 적어놓고 본문이 아무것도
    return 하지 않아 늘 None(falsy)이었다. main() 이 그 값으로 종료코드를 정하므로 **전송에
    성공해도 워크플로가 빨갛게 죽었다**. test_grab.py 는 notify 를 통째로 몽키패치해서 이걸
    못 잡는다 — 반환값 계약은 여기서 고정한다.
    """
    saved = {k: os.environ.get(k) for k in ("DISCORD_BOT_TOKEN", "DISCORD_CHANNEL", "DISCORD_USER_ID")}
    real_urlopen = urllib.request.urlopen
    try:
        os.environ["DISCORD_BOT_TOKEN"] = "tok"
        os.environ["DISCORD_CHANNEL"] = "1"
        os.environ.pop("DISCORD_USER_ID", None)

        urllib.request.urlopen = lambda *_a, **_kw: io.BytesIO(b"{}")
        assert notify("x") is True  # 성공 경로가 True 를 돌려준다

        def boom(*_a, **_kw):
            raise OSError("boom")

        urllib.request.urlopen = boom
        with contextlib.redirect_stdout(io.StringIO()):
            assert notify("x") is False  # 실패는 삼키되 False 를 돌려준다

        del os.environ["DISCORD_BOT_TOKEN"]
        with contextlib.redirect_stdout(io.StringIO()):
            assert notify("x") is False  # 미설정도 False
    finally:
        urllib.request.urlopen = real_urlopen
        for k, v in saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v


def selftest():
    assert dday(date(2026, 8, 11)) == "D-16"
    assert dday(DELETE_ETA) == "D-DAY"
    assert dday(date(2026, 8, 30)) == "D+3"
    assert verdict(404, "NotAuthorizedOrNotFound") == "deleted"
    # 401 은 판정 보류다 — 자격증명 파손이 훨씬 흔하고, 재확인도 같은 키로 타서 못 거른다.
    # (근거·감수하는 미탐 위험은 DELETED_CODES 주석) 이 어서션이 그 결정을 고정한다.
    assert verdict(401, "NotAuthenticated") == "unknown"
    assert verdict(404, "") == "deleted"
    assert verdict(429, "TooManyRequests") == "unknown"
    assert verdict(500, "InternalError") == "unknown"
    assert verdict(503, "ServiceUnavailable") == "unknown"
    # 텔레그램 평문화 — 실제 발송 문구에 마크다운 기호가 남으면 그대로 노출된다.
    # 본문 전체를 통째로 고정한다: 이 4줄이 운영자가 확정한 형식이고, 한 줄이라도 늘면
    # "던지면 Claude 가 처리한다"는 전제가 흐려진다(절차는 파일 위 주석이 보관).
    plain = to_plain(next_steps(date(2026, 8, 27)))
    assert plain == (
        "[26년 8월 27일]\n💼 oci_arm_grabber\n🚨 오라클 계정 삭제완료\n- 새 계정 가입 필요"
    ), plain
    assert "**" not in plain and "`" not in plain, plain
    assert to_plain("-# 각주\n**굵게** `코드` <https://a.b/c>") == "각주\n굵게 코드 https://a.b/c"
    # `-#` 뒤가 개행뿐이어도 줄을 합치지 않는다(\s 를 쓰면 다음 줄이 끌려 올라온다).
    assert to_plain("-#\n다음 줄") == "\n다음 줄"
    # 발신 문구 3종을 전문으로 고정한다 — 운영자가 폰에서 확정한 형태이므로 형식이 곧 계약이다.
    _d = date(2026, 8, 16)
    alive = status_msg("alive", "", _d, "D-11")
    assert alive == "🕒 오라클 계정 존재\n\n예상 삭제 26-08-27(D-11)", alive
    assert "\n\n" in alive, "제목·상세는 두 문단이다 — 한 줄로 붙이지 마라"
    hold = to_plain(status_msg("unknown", "ServiceError 401 NotAuthenticated", _d, "D-11"))
    assert hold.startswith("⚠️ 오라클 계정 상태 확인 실패"), hold
    assert "삭제된 것 아님" in hold and "**" not in hold, hold
    assert status_msg("deleted", "", _d, "D-11") == next_steps(_d)
    tg_selftest()
    notify_selftest()
    print("selftest ok")


def main():
    if "--selftest" in sys.argv:  # OCI 호출 없이 판정 로직만 검증
        selftest()
        return
    cfg, _cc, _net = build_clients()  # grab.py 와 동일한 config(컴퓨트/네트워크 클라이언트는 미사용)
    state, why = probe(cfg)
    if state == "deleted":  # 오탐 방지 — 일시적 404 면 재조회에서 alive 로 돌아온다
        print(f"deleted? rechecking in {RECHECK_SEC}s")
        time.sleep(RECHECK_SEC)
        state, why = probe(cfg)
    today = datetime.now(KST).date()
    tag = dday(today)
    print(f"tenancy {state} ({tag}) {why}")
    # 발신은 **텔레그램 감시 봇 하나**다(2026-08-16 운영자 지시 — 디스코드 발송 제거).
    # 세 상태가 같은 경로를 타므로 종료코드 판정도 한 군데로 모인다(`and` 합성이 사라졌다).
    sent = tg(status_msg(state, why, today, tag))
    if not sent:
        # 전송 실패를 삼키면 워크플로는 초록인데 알림은 안 온다 = 감시가 없는 것과 같다.
        sys.exit(1)


if __name__ == "__main__":
    main()
