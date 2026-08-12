"""
邮箱真实性验证 API (Email Verifier API)
=========================================
寻光一刻（上海）智能科技有限公司 · Carpe Lux Technology

功能：输入邮箱地址，通过 SMTP 握手验证该邮箱是否真实存在。
原理：连接目标邮箱的邮件服务器 → 尝试 RCPT TO 命令 → 服务器会告诉我们
     这个收件人是否存在（550 = 不存在，250 = 存在）。
      不实际发送任何邮件，只是"敲门"验证。

成本：零 Token。纯网络协议验证。
"""

import re
import socket
import smtplib
import asyncio
import time
from typing import Optional
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

app = FastAPI(
    title="Email Verifier API - 邮箱真实性验证",
    description="输入邮箱地址，验证它是否真实存在（SMTP 握手验证，不发送邮件）。"
                "支持一次性检查、批量检查、MX 记录查询。",
    version="1.0.0",
    docs_url="/docs",
)

# ============================================================
# 1. 基础工具函数
# ============================================================

EMAIL_RE = re.compile(r"^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$")

# 常见一次性邮箱域名（临时邮箱）
DISPOSABLE_DOMAINS = {
    "mailinator.com", "10minutemail.com", "guerrillamail.com",
    "temp-mail.org", "throwawaymail.com", "yopmail.com",
    "maildrop.cc", "trashmail.com", "getnada.com", "tempmail.com",
    "sharklasers.com", "spam4.me", "mytemp.email", "dispostable.com",
    "mailnesia.com", "mintemail.com", "spamgourmet.com", "emailfake.com",
    "fakeinbox.com", "tempinbox.com", "mailcatch.com", "maileater.com",
}

# 国内常见邮箱域名（MX 记录快速检查白名单）
COMMON_DOMAINS = {
    "qq.com", "163.com", "126.com", "sina.com", "sina.cn",
    "sohu.com", "gmail.com", "outlook.com", "hotmail.com", "icloud.com",
    "foxmail.com", "aliyun.com", "139.com", "189.cn", "yahoo.com",
    "protonmail.com", "hey.com", "yahoo.co.jp",
}


# 简单的MX查询缓存（减少重复DNS查询，缓存10分钟）
_MX_CACHE = {}
_MX_CACHE_TTL = 600


def get_mx_servers(domain: str) -> list[str]:
    """查询域名的 MX 记录（邮件服务器地址），带10分钟缓存"""
    import time as _t
    now = _t.time()
    cached = _MX_CACHE.get(domain)
    if cached and now - cached[0] < _MX_CACHE_TTL:
        return cached[1]
    try:
        import dns.resolver
        resolver = dns.resolver.Resolver()
        resolver.timeout = 2.0
        resolver.lifetime = 3.0
        answers = resolver.resolve(domain, "MX")
        mx_list = sorted(
            [(r.preference, str(r.exchange).rstrip(".")) for r in answers],
            key=lambda x: x[0],
        )
        result = [mx for _, mx in mx_list]
    except Exception:
        # 无 dnspython 时用 socket 兜底（只能查 A 记录，不准确）
        try:
            result = [socket.gethostbyname(domain)]
        except Exception:
            result = []
    _MX_CACHE[domain] = (now, result)
    return result


def smtp_verify(email: str, timeout: float = 8.0) -> dict:
    """
    SMTP 握手验证单个邮箱（原始 socket 实现）。
    返回验证结果字典。

    说明：为什么不用 smtplib 库？
    - smtplib.SMTP() 会自动尝试 STARTTLS 升级，国内邮件服务器
      （QQ/163等）在无证书上下文时协商会卡死超时（实测 TIMEOUT）
    - 原始 socket 直接 EHLO → MAIL FROM → RCPT TO 三步对话，
      国内服务器响应正常（实测 250 OK / 550 拒绝）
    - 同时避免部分服务器对 smtplib 默认 banner 的反垃圾拦截
    """
    domain = email.split("@")[1]
    mx_servers = get_mx_servers(domain)

    if not mx_servers:
        return {
            "valid": False,
            "reason": "NO_MX_RECORD",
            "detail": "该域名没有配置邮件服务器（MX记录），邮箱不可能存在",
        }

    # 只尝试第1个MX（云IP屏蔽时第一个就超时，试第2个纯属浪费时间）
    deadline = time.time() + timeout
    for mx in mx_servers[:1]:
        try:
            remaining = max(0.5, deadline - time.time())
            result = _raw_smtp_rcpt(mx, email, remaining)
            if result is not None:
                return result
        except (socket.timeout, ConnectionRefusedError, OSError):
            break
        except Exception:
            break
    # 连接层失败 = 云IP被屏蔽的典型信号（DNS能解析但25端口无响应），立即降级
    return {
        "valid": None,
        "reason": "TIMEOUT",
        "detail": "无法连接邮件服务器（云服务器IP常被邮件服务商屏蔽），无法确定",
    }


def _raw_smtp_rcpt(mx: str, email: str, timeout: float = 8.0):
    """原始 socket 执行 SMTP 三步对话，返回验证结果或 None（需换下一个MX）"""
    try:
        # 只解析第一个IP再连接：create_connection 会遍历MX的所有A记录，
        # 163等服务器有5-6个IP且对云IP丢弃SYN，逐个等超时=10-15s（实测）
        ip = socket.gethostbyname(mx)
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((ip, 25))
    except Exception:
        return None
    s.settimeout(timeout)
    try:
        f = s.makefile("rb")

        def read_reply():
            lines = []
            while True:
                line = f.readline()
                if not line:
                    break
                line = line.decode("utf-8", "ignore").strip()
                lines.append(line)
                if len(line) >= 3 and (len(line) == 3 or line[3] != "-"):
                    break
            return lines

        # 1. 欢迎语
        read_reply()
        # 2. EHLO（伪装成普通发信服务器）
        s.sendall(b"EHLO mail.carpeluxtech.com\r\n")
        read_reply()
        # 3. MAIL FROM
        s.sendall(b"MAIL FROM:<verify@carpeluxtech.com>\r\n")
        read_reply()
        # 4. RCPT TO —— 关键验证
        s.sendall(f"RCPT TO:<{email}>\r\n".encode("utf-8"))
        rcpt_reply = read_reply()
        s.sendall(b"QUIT\r\n")
        s.close()

        if not rcpt_reply:
            return None
        code = int(rcpt_reply[0][:3]) if rcpt_reply[0][:3].isdigit() else 0
        msg = "; ".join(rcpt_reply)

        if code in (250, 251, 252):
            return {"valid": True, "reason": "ACCEPTED", "detail": "邮件服务器确认该收件人存在", "mx": mx, "confidence": "high"}
        if code in (450, 451, 452):
            return {"valid": None, "reason": "TRY_AGAIN", "detail": f"服务器临时性拒绝（{code}），邮箱状态无法确定", "mx": mx, "confidence": "low"}
        if code in (500, 501, 502, 503, 504):
            return None  # 协议错误，换下一个MX
        # 550/551/553 = 明确拒绝 = 不存在（但大厂反探测可能误报，标记置信度）
        confident = domain not in ("gmail.com", "outlook.com", "hotmail.com", "yahoo.com", "protonmail.com", "icloud.com")
        return {
            "valid": False, "reason": "REJECTED",
            "detail": f"邮件服务器拒绝（{code}），该邮箱不存在" + ("" if confident else "（注：该邮箱服务商反垃圾策略严格，结果仅供参考）"),
            "mx": mx, "confidence": "high" if confident else "medium",
        }
    except (socket.timeout, OSError):
        try:
            s.close()
        except Exception:
            pass
        return None
    except Exception:
        try:
            s.close()
        except Exception:
            pass
        return None


# ============================================================
# 2. API 接口定义
# ============================================================

class EmailCheckRequest(BaseModel):
    email: str
    deep_check: bool = True


class EmailCheckResult(BaseModel):
    email: str
    valid: Optional[bool]
    reason: str
    detail: str
    format_ok: bool = False
    disposable: bool = False
    confidence: str = "high"
    mx_servers: list = []


@app.get("/")
def root():
    return {
        "service": "Email Verifier API",
        "status": "running",
        "docs": "/docs",
        "version": "1.0.0",
    }


@app.post("/verify", response_model=EmailCheckResult)
def verify_email(request: EmailCheckRequest):
    """验证单个邮箱是否真实存在"""
    email = request.email.strip().lower()

    # 1. 格式检查
    if not EMAIL_RE.match(email):
        return EmailCheckResult(
            email=email, valid=False, reason="INVALID_FORMAT",
            detail="邮箱格式不正确", format_ok=False,
        )

    domain = email.split("@")[1]

    # 2. 一次性邮箱检查
    disposable = domain in DISPOSABLE_DOMAINS

    # 3. 深度检查（SMTP握手）——云服务器IP常被邮件商屏蔽，超时自动降级
    if request.deep_check:
        t0 = time.time()
        result = smtp_verify(email, timeout=2.0)  # 单MX最多2秒，总上限~4秒
        elapsed = time.time() - t0
        # 云服务器IP被屏蔽时（全部TIMEOUT），降级为浅检查结果并标注
        if result.get("valid") is None and result.get("reason") == "TIMEOUT":
            return EmailCheckResult(
                email=email, valid=None, reason="LIGHT_FALLBACK",
                detail="SMTP深度验证被邮件服务器屏蔽（云IP常见），已降级为浅检查：格式+MX+一次性域名均正常",
                format_ok=True, disposable=disposable,
                confidence="medium",
                mx_servers=get_mx_servers(domain),
            )
        result["email"] = email
        result["format_ok"] = True
        result["disposable"] = disposable
        result["mx_servers"] = get_mx_servers(domain)
        result["elapsed"] = round(elapsed, 2)
        return EmailCheckResult(**result)
    else:
        return EmailCheckResult(
            email=email, valid=None, reason="LIGHT_CHECK",
            detail="浅检查模式：仅格式+一次性域名检测，未做SMTP验证",
            format_ok=True, disposable=disposable,
            mx_servers=get_mx_servers(domain),
        )


class BatchCheckRequest(BaseModel):
    emails: list[str]
    deep_check: bool = True


@app.post("/verify/batch", response_model=dict)
def verify_batch(request: BatchCheckRequest):
    """批量验证邮箱（最多50个）"""
    if len(request.emails) > 50:
        raise HTTPException(400, "单次最多50个邮箱")
    results = []
    for email in request.emails:
        results.append(verify_email(EmailCheckRequest(email=email, deep_check=request.deep_check)))
    valid_count = sum(1 for r in results if r.valid is True)
    invalid_count = sum(1 for r in results if r.valid is False)
    return {
        "total": len(results),
        "valid": valid_count,
        "invalid": invalid_count,
        "unknown": len(results) - valid_count - invalid_count,
        "results": [r.dict() for r in results],
    }


@app.get("/mx/{domain}")
def mx_lookup(domain: str):
    """查询域名的 MX 记录"""
    mx = get_mx_servers(domain)
    return {"domain": domain, "mx_servers": mx, "count": len(mx)}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
