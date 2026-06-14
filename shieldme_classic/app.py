"""
Shield Me Backend
A defensive Flask API for checking files and URLs.

This server does not execute uploaded files. It only reads bytes/text and searches
for known suspicious indicators. The AI model can be connected later through the
`run_ai_model_placeholder` function without changing the frontend contract.
"""

from __future__ import annotations

import hashlib
import os
import re
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Tuple
from urllib.parse import parse_qs, unquote, urlparse

try:
    from dotenv import load_dotenv
except ImportError:  # keep the app usable even without python-dotenv
    def load_dotenv(*args: Any, **kwargs: Any) -> bool:
        return False

from flask import Flask, jsonify, request
from flask_cors import CORS
from werkzeug.exceptions import RequestEntityTooLarge
from werkzeug.utils import secure_filename

BASE_DIR = Path(__file__).resolve().parent
load_dotenv(BASE_DIR / ".env")

MAX_FILE_SIZE_MB = int(os.getenv("MAX_FILE_SIZE_MB", "10"))
MAX_FILE_COUNT = int(os.getenv("MAX_FILE_COUNT", "8"))
REQUEST_LIMIT_BYTES = MAX_FILE_SIZE_MB * MAX_FILE_COUNT * 1024 * 1024
CORS_ORIGINS = os.getenv("CORS_ORIGINS", "*")

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = REQUEST_LIMIT_BYTES

CORS(
    app,
    resources={
        r"/*": {
            "origins": "*" if CORS_ORIGINS == "*" else [o.strip() for o in CORS_ORIGINS.split(",") if o.strip()]
        }
    },
)

URL_PATTERN = re.compile(r"https?://[^\s<>()\[\]{}\"']+", re.IGNORECASE)
IP_HOST_PATTERN = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")

SUSPICIOUS_TERMS = {
    "free nitro": "وعد بهدية أو اشتراك مجاني، وهو نمط شائع في رسائل الاحتيال.",
    "discord nitro": "رسائل العروض المجانية على Discord تُستخدم كثيرًا في سرقة الحسابات.",
    "verify your account": "طلب تحقق عاجل من الحساب قد يكون محاولة تصيد.",
    "password": "ذكر كلمة المرور داخل الرسالة يحتاج حذرًا إضافيًا.",
    "login": "روابط تسجيل الدخول داخل رسائل غير موثوقة تحتاج فحصًا.",
    "wallet": "رسائل المحافظ الرقمية قد تستهدف سرقة الأموال أو البيانات الحساسة.",
    "seed phrase": "طلب Seed Phrase مؤشر خطير جدًا ولا يجب مشاركته أبدًا.",
    "urgent": "استخدام الاستعجال أسلوب شائع في الهندسة الاجتماعية.",
    "limited time": "استخدام الضغط الزمني قد يكون جزءًا من محاولة احتيال.",
    "gift": "العروض والهدايا غير المتوقعة تحتاج تحققًا من المصدر.",
    "ربحت": "رسائل الفوز المفاجئ قد تكون محاولة احتيال.",
    "كلمة المرور": "لا تشارك كلمة المرور أو تدخلها في روابط غير موثوقة.",
    "تحقق من حسابك": "طلب التحقق من الحساب عبر رابط يحتاج حذرًا.",
    "مجاني": "العروض المجانية غير المتوقعة قد تُستخدم لجذب الضحية.",
    "هدية": "رسائل الهدايا قد تخفي روابط تصيد.",
}

SHORTENER_DOMAINS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "is.gd",
    "cutt.ly",
    "shorturl.at",
    "ow.ly",
    "rebrand.ly",
    "lnkd.in",
}

SUSPICIOUS_TLDS = {"zip", "mov", "click", "top", "xyz", "tk", "ml", "ga", "cf", "quest", "country"}
BRAND_KEYWORDS = {"paypal", "google", "facebook", "instagram", "microsoft", "apple", "binance", "discord"}

SEVERITY_POINTS = {
    "info": 0,
    "low": 12,
    "medium": 25,
    "high": 45,
    "critical": 70,
}

STATUS_LABELS = {
    "clean": "آمن مبدئيًا",
    "low": "منخفض",
    "medium": "متوسط",
    "high": "مرتفع",
    "critical": "حرج",
    "malicious": "خطر",
    "warning": "تحذير",
    "info": "معلومة",
}

FILE_SIGNATURES: List[Dict[str, Any]] = [
    {
        "id": "PDF_SCRIPT_ACTION",
        "title": "سلوك تلقائي داخل PDF",
        "category": "document",
        "severity": "high",
        "description": "الملف يحتوي على مؤشرات تشغيل تلقائي أو سكربت داخل مستند PDF.",
        "patterns": [b"/javascript", b"/js", b"/openaction", b"/aa", b"/launch"],
        "min_hits": 2,
    },
    {
        "id": "OFFICE_MACRO_EXECUTION",
        "title": "أوامر Macro مشبوهة",
        "category": "document",
        "severity": "high",
        "description": "المستند يحتوي على مؤشرات Macro قد تُستخدم لتنفيذ أوامر على الجهاز.",
        "patterns": [b"autoopen", b"document_open", b"createobject", b"wscript.shell", b"shell.application", b"powershell"],
        "min_hits": 2,
    },
    {
        "id": "RANSOMWARE_BACKUP_TAMPERING",
        "title": "محاولة تعطيل النسخ الاحتياطية",
        "category": "ransomware",
        "severity": "critical",
        "description": "تم العثور على أوامر شائعة في هجمات الفدية لتعطيل أو حذف النسخ الاحتياطية.",
        "patterns": [b"vssadmin delete shadows", b"wmic shadowcopy delete", b"delete shadows /all", b"bcdedit /set", b"recoveryenabled no"],
        "min_hits": 1,
    },
    {
        "id": "HIDDEN_SCRIPT_EXECUTION",
        "title": "تشغيل أوامر مخفية",
        "category": "script",
        "severity": "high",
        "description": "الملف يحتوي على مؤشرات تشغيل أوامر مخفية أو تجاوز سياسات التنفيذ.",
        "patterns": [b"-windowstyle hidden", b"-w hidden", b"executionpolicy bypass", b"-nop", b"-encodedcommand", b"frombase64string"],
        "min_hits": 1,
    },
    {
        "id": "BROWSER_DATA_ACCESS",
        "title": "استهداف بيانات المتصفح",
        "category": "infostealer",
        "severity": "critical",
        "description": "تم العثور على مؤشرات قد تستهدف كلمات المرور أو الكوكيز أو بيانات المتصفح.",
        "patterns": [b"login data", b"local state", b"cookies", b"web data", b"chrome\\user data", b"password_value"],
        "min_hits": 2,
    },
    {
        "id": "TOKEN_EXFILTRATION",
        "title": "احتمال سرقة رموز جلسات",
        "category": "infostealer",
        "severity": "high",
        "description": "الملف يحتوي على مؤشرات قد تُستخدم لجمع أو إرسال Tokens إلى جهة خارجية.",
        "patterns": [b"discord token", b"authorization", b"webhook", b"api_token", b"telegram bot", b"sendmessage"],
        "min_hits": 2,
    },
    {
        "id": "KEYBOARD_MONITORING",
        "title": "مراقبة إدخال لوحة المفاتيح",
        "category": "spyware",
        "severity": "critical",
        "description": "تم العثور على مؤشرات وظائف تُستخدم غالبًا لتسجيل ضغطات لوحة المفاتيح.",
        "patterns": [b"getasynckeystate", b"setwindowshookex", b"getforegroundwindow", b"keybd_event"],
        "min_hits": 1,
    },
    {
        "id": "PROCESS_INJECTION",
        "title": "حقن داخل العمليات",
        "category": "trojan",
        "severity": "critical",
        "description": "الملف يحتوي على مؤشرات حقن ذاكرة داخل عمليات أخرى.",
        "patterns": [b"virtualalloc", b"writeprocessmemory", b"createremotethread", b"openprocess", b"loadlibrarya"],
        "min_hits": 2,
    },
    {
        "id": "SERVER_CONTROL_SCRIPT",
        "title": "أوامر تحكم بالخادم",
        "category": "web",
        "severity": "high",
        "description": "الملف يحتوي على مؤشرات سكربت تحكم يمكن أن يُستخدم لتنفيذ أوامر على الخادم.",
        "patterns": [b"<?php", b"system(", b"shell_exec", b"passthru", b"cmd.exe", b"eval($_"],
        "min_hits": 2,
    },
    {
        "id": "SUSPICIOUS_DOWNLOAD_EXECUTE",
        "title": "تحميل وتشغيل محتوى خارجي",
        "category": "dropper",
        "severity": "medium",
        "description": "الملف يحتوي على مؤشرات تحميل ملف من الإنترنت ثم تشغيله.",
        "patterns": [b"invoke-webrequest", b"downloadstring", b"start-process", b"curl ", b"bitsadmin", b"certutil -urlcache"],
        "min_hits": 2,
    },
]

SAFE_ADVICE = [
    "استمر في تحميل الملفات من مصادر موثوقة فقط.",
    "افحص الملفات المهمة قبل فتحها، خصوصًا الملفات القادمة من البريد أو الرسائل.",
    "تأكد من تحديث نظام التشغيل والمتصفح باستمرار.",
]

DANGER_ADVICE = [
    "لا تفتح الملف ولا تشغّله على جهازك.",
    "احذف الملف أو اعزله في بيئة آمنة إذا كنت تحتاج لتحليله.",
    "لا تدخل كلمات مرور أو بيانات حساسة في أي رابط مشبوه.",
    "إذا وصلك الملف من شخص تعرفه، تواصل معه من قناة أخرى للتأكد.",
]

WARNING_ADVICE = [
    "تعامل مع الملف أو الرابط بحذر وتأكد من المصدر.",
    "لا تمنح أي صلاحيات أو توافق على تشغيل Macro أو سكربتات.",
    "استخدم جهازًا أو بيئة اختبار آمنة إذا كنت مضطرًا لفتحه.",
]


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def clamp(value: int, minimum: int = 0, maximum: int = 100) -> int:
    return max(minimum, min(maximum, value))


def status_from_score(score: int) -> str:
    if score >= 75:
        return "critical"
    if score >= 50:
        return "high"
    if score >= 25:
        return "medium"
    if score >= 10:
        return "low"
    return "clean"


def overall_status_from_items(items: Iterable[Dict[str, Any]]) -> str:
    statuses = [item.get("status") or item.get("risk_level") for item in items]
    if any(s in {"critical", "high", "malicious"} for s in statuses):
        return "malicious"
    if any(s in {"medium", "low", "warning"} for s in statuses):
        return "warning"
    return "clean"


def safe_filename(filename: str) -> str:
    secured = secure_filename(filename or "uploaded_file")
    return secured or "uploaded_file"


def human_size(size: int) -> str:
    if size >= 1024 * 1024:
        return f"{size / (1024 * 1024):.2f} MB"
    if size >= 1024:
        return f"{size / 1024:.1f} KB"
    return f"{size} B"


def sha256_short(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()[:16]


def pattern_hits(content_lower: bytes, patterns: List[bytes]) -> List[str]:
    hits = []
    for pattern in patterns:
        if pattern.lower() in content_lower:
            try:
                hits.append(pattern.decode("utf-8", errors="ignore"))
            except Exception:
                hits.append(str(pattern))
    return hits


def analyze_file_content(filename: str, content: bytes) -> Dict[str, Any]:
    filename_clean = safe_filename(filename)
    size = len(content)
    content_lower = content.lower()
    indicators: List[Dict[str, Any]] = []
    risk_score = 0

    for signature in FILE_SIGNATURES:
        hits = pattern_hits(content_lower, signature["patterns"])
        if len(hits) >= int(signature.get("min_hits", 1)):
            severity = signature["severity"]
            points = SEVERITY_POINTS.get(severity, 25)
            risk_score += points
            indicators.append(
                {
                    "id": signature["id"],
                    "title": signature["title"],
                    "severity": severity,
                    "category": signature["category"],
                    "description": signature["description"],
                    "evidence": hits[:5],
                }
            )

    extension = Path(filename_clean).suffix.lower().lstrip(".")
    if extension in {"exe", "bat", "cmd", "ps1", "vbs", "js", "scr"} and not indicators:
        risk_score += 10
        indicators.append(
            {
                "id": "EXECUTABLE_FILE_TYPE",
                "title": "نوع ملف قابل للتنفيذ",
                "severity": "low",
                "category": "file_type",
                "description": "نوع الملف يمكنه تنفيذ أوامر على الجهاز، لذلك يحتاج حذرًا حتى لو لم تظهر مؤشرات واضحة.",
                "evidence": [extension],
            }
        )

    risk_score = clamp(risk_score)
    risk_level = status_from_score(risk_score)

    if risk_level == "clean":
        message = "لم تظهر مؤشرات خطورة واضحة في الفحص المبدئي لهذا الملف."
        advice = SAFE_ADVICE
    elif risk_level in {"low", "medium"}:
        message = "تم العثور على مؤشرات تحتاج مراجعة قبل فتح الملف."
        advice = WARNING_ADVICE
    else:
        message = "تم العثور على مؤشرات خطورة عالية. لا تفتح الملف قبل التأكد من مصدره."
        advice = DANGER_ADVICE

    return {
        "type": "file",
        "filename": filename_clean,
        "size_bytes": size,
        "size_label": human_size(size),
        "hash_preview": sha256_short(content),
        "status": risk_level,
        "risk_level": risk_level,
        "risk_score": risk_score,
        "risk_percent": risk_score,
        "message": message,
        "indicators": indicators,
        "advice": advice,
        # compatibility with older frontend versions
        "matches": [
            {
                "rule": item["id"],
                "severity": item["severity"],
                "category": item["category"],
                "description": item["description"],
            }
            for item in indicators
        ],
    }


def normalize_url(raw_url: str) -> str:
    return raw_url.rstrip(".,;،)］]}")


def count_digits(text: str) -> int:
    return sum(ch.isdigit() for ch in text)


def analyze_url(raw_url: str) -> Dict[str, Any]:
    clean_url = normalize_url(raw_url)
    decoded = unquote(clean_url)
    parsed = urlparse(decoded)
    host = parsed.hostname or ""
    host_lower = host.lower().strip(".")
    path_lower = (parsed.path or "").lower()
    query = parse_qs(parsed.query)
    indicators: List[Dict[str, Any]] = []
    risk_score = 0

    def add_indicator(title: str, description: str, severity: str = "medium") -> None:
        nonlocal risk_score
        risk_score += SEVERITY_POINTS.get(severity, 25)
        indicators.append({"title": title, "description": description, "severity": severity})

    if parsed.scheme == "http":
        add_indicator("اتصال غير مشفر", "الرابط يستخدم HTTP بدل HTTPS.", "medium")

    if not host_lower:
        add_indicator("رابط غير مكتمل", "لم نستطع استخراج اسم النطاق من الرابط.", "medium")
    else:
        if host_lower in SHORTENER_DOMAINS:
            add_indicator("رابط مختصر", "الرابط المختصر قد يخفي الوجهة الحقيقية.", "medium")

        if IP_HOST_PATTERN.match(host_lower):
            add_indicator("عنوان IP مباشر", "استخدام IP بدل اسم نطاق واضح قد يكون مؤشرًا مشبوهًا.", "high")

        if host_lower.startswith("xn--") or ".xn--" in host_lower:
            add_indicator("نطاق مشفر بصريًا", "النطاق يستخدم Punycode وقد يحاول تقليد موقع معروف.", "high")

        tld = host_lower.rsplit(".", 1)[-1] if "." in host_lower else ""
        if tld in SUSPICIOUS_TLDS:
            add_indicator("امتداد يحتاج حذرًا", f"امتداد .{tld} يظهر كثيرًا في حملات احتيال أو روابط غير موثوقة.", "medium")

        if host_lower.count("-") >= 3:
            add_indicator("نطاق غير معتاد", "النطاق يحتوي على شرطات كثيرة وقد يكون مُصممًا لتضليل المستخدم.", "low")

        for brand in BRAND_KEYWORDS:
            if brand in host_lower and not host_lower.endswith(f"{brand}.com") and f".{brand}." not in host_lower:
                add_indicator("احتمال تقليد علامة تجارية", f"النطاق يحتوي على كلمة {brand} لكنه لا يبدو نطاقًا رسميًا واضحًا.", "medium")
                break

    risky_words = ["login", "verify", "account", "password", "wallet", "gift", "free", "secure", "update", "billing"]
    risky_hits = [word for word in risky_words if word in path_lower or word in decoded.lower()]
    if len(risky_hits) >= 2:
        add_indicator("كلمات حساسة في الرابط", "الرابط يحتوي على كلمات مرتبطة بتسجيل الدخول أو التحقق أو الهدايا.", "medium")

    if len(decoded) > 140:
        add_indicator("رابط طويل جدًا", "طول الرابط قد يُستخدم لإخفاء الوجهة أو إضافة تتبع زائد.", "low")

    if count_digits(host_lower) >= 6:
        add_indicator("أرقام كثيرة في النطاق", "وجود أرقام كثيرة داخل النطاق قد يكون مؤشرًا غير طبيعي.", "low")

    if len(query) >= 6:
        add_indicator("معاملات كثيرة", "الرابط يحتوي على عدد كبير من معاملات التتبع أو الإخفاء.", "low")

    risk_score = clamp(risk_score)
    risk_level = status_from_score(risk_score)

    return {
        "type": "url",
        "url": clean_url,
        "host": host,
        "status": risk_level,
        "risk_level": risk_level,
        "risk_score": risk_score,
        "risk_percent": risk_score,
        "message": "لم تظهر مؤشرات خطورة واضحة في الرابط." if not indicators else "تم العثور على مؤشرات تحتاج مراجعة في الرابط.",
        "indicators": indicators,
        "advice": SAFE_ADVICE if risk_level == "clean" else (WARNING_ADVICE if risk_level in {"low", "medium"} else DANGER_ADVICE),
    }


def analyze_text_message(text: str) -> Dict[str, Any]:
    original = (text or "").strip()
    lowered = original.lower()
    urls = [normalize_url(url) for url in URL_PATTERN.findall(original)]
    url_results = [analyze_url(url) for url in urls]
    indicators: List[Dict[str, Any]] = []
    risk_score = 0

    for term, description in SUSPICIOUS_TERMS.items():
        if term in lowered:
            risk_score += 12
            indicators.append({"title": "مؤشر في النص", "description": description, "severity": "low"})

    if url_results:
        risk_score += max((item["risk_score"] for item in url_results), default=0)

    risk_score = clamp(risk_score)
    risk_level = status_from_score(risk_score)

    if not original:
        summary = "لم يتم إرسال نص للفحص."
    elif url_results and risk_level in {"critical", "high"}:
        summary = "الفحص المبدئي وجد مؤشرات خطورة عالية في الرابط. تجنب فتحه أو إدخال أي بيانات."
    elif url_results and risk_level in {"medium", "low"}:
        summary = "الفحص المبدئي وجد مؤشرات تحتاج حذرًا. تأكد من المصدر قبل التعامل مع الرابط."
    elif url_results:
        summary = "لم تظهر مؤشرات خطورة واضحة في الرابط، لكن تأكد دائمًا من المصدر قبل إدخال بياناتك."
    elif indicators:
        summary = "تم العثور على مؤشرات نصية تحتاج حذرًا."
    else:
        summary = "تم استلام النص ولم تظهر مؤشرات واضحة. يمكنك أيضًا رفع ملف أو إرسال رابط للفحص."

    return {
        "type": "text",
        "status": risk_level,
        "risk_level": risk_level,
        "risk_score": risk_score,
        "risk_percent": risk_score,
        "summary": summary,
        "message": summary,
        "indicators": indicators,
        "urls": url_results,
        "advice": SAFE_ADVICE if risk_level == "clean" else (WARNING_ADVICE if risk_level in {"low", "medium"} else DANGER_ADVICE),
    }


def run_ai_model_placeholder(_: Dict[str, Any]) -> Dict[str, Any]:
    """Placeholder for your team's model integration.

    Keep this response stable so the frontend can show the same cards after the
    real model is added.
    """
    return {
        "enabled": False,
        "status": "pending",
        "label": None,
        "confidence": None,
    }


def build_reply(status: str, total_files: int, total_urls: int) -> str:
    if status == "malicious":
        return "تم العثور على مؤشرات خطورة عالية. يفضّل عدم فتح العنصر قبل التأكد من مصدره."
    if status == "warning":
        return "تم العثور على مؤشرات تحتاج مراجعة. تعامل بحذر وتأكد من المصدر."
    if total_files or total_urls:
        return "انتهى الفحص المبدئي ولم تظهر مؤشرات خطورة واضحة."
    return "أرسل رابطًا أو ارفع ملفًا للحصول على نتيجة فحص واضحة."


@app.errorhandler(RequestEntityTooLarge)
def handle_too_large(_: RequestEntityTooLarge):
    return (
        jsonify(
            {
                "status": "error",
                "code": "request_too_large",
                "message": f"حجم الطلب أكبر من الحد المسموح. الحد الحالي {MAX_FILE_SIZE_MB}MB لكل ملف وحتى {MAX_FILE_COUNT} ملفات.",
            }
        ),
        413,
    )


@app.get("/")
def index() -> Any:
    return jsonify(
        {
            "name": "Shield Me API",
            "status": "online",
            "message": "API is running. Use /health or POST /scan.",
        }
    )


@app.get("/health")
def health() -> Any:
    return jsonify(
        {
            "status": "ok",
            "scanner_ready": True,
            "ai_model_status": "pending",
            "max_file_size_mb": MAX_FILE_SIZE_MB,
            "max_file_count": MAX_FILE_COUNT,
            "time": utc_now_iso(),
        }
    )


@app.post("/scan")
def scan() -> Any:
    started = time.time()
    user_text = (request.form.get("text") or "").strip()
    uploaded_files = request.files.getlist("file")

    if len(uploaded_files) > MAX_FILE_COUNT:
        return (
            jsonify(
                {
                    "status": "error",
                    "code": "too_many_files",
                    "message": f"الحد الأقصى هو {MAX_FILE_COUNT} ملفات في الطلب الواحد.",
                }
            ),
            400,
        )

    file_results: List[Dict[str, Any]] = []
    for uploaded_file in uploaded_files:
        if not uploaded_file or not uploaded_file.filename:
            continue

        filename = safe_filename(uploaded_file.filename)
        content = uploaded_file.read()
        if len(content) > MAX_FILE_SIZE_MB * 1024 * 1024:
            file_results.append(
                {
                    "type": "file",
                    "filename": filename,
                    "status": "critical",
                    "risk_level": "critical",
                    "risk_score": 100,
                    "risk_percent": 100,
                    "message": f"حجم الملف أكبر من الحد المسموح ({MAX_FILE_SIZE_MB}MB).",
                    "indicators": [
                        {
                            "title": "حجم غير مسموح",
                            "description": "تم رفض الملف لحماية الخادم من الطلبات الكبيرة.",
                            "severity": "high",
                        }
                    ],
                    "advice": ["ارفع ملفًا أصغر أو افحصه في بيئة مخصصة."],
                    "matches": [],
                }
            )
            continue

        file_results.append(analyze_file_content(filename, content))

    text_analysis = analyze_text_message(user_text) if user_text else None
    url_results = text_analysis.get("urls", []) if text_analysis else []

    status_items: List[Dict[str, Any]] = []
    status_items.extend(file_results)
    if text_analysis and (user_text or url_results):
        status_items.append(text_analysis)
    overall_status = overall_status_from_items(status_items) if status_items else "clean"

    malicious_count = sum(1 for item in file_results if item["status"] in {"critical", "high", "malicious"})
    warning_count = sum(1 for item in file_results if item["status"] in {"low", "medium", "warning"})
    clean_count = sum(1 for item in file_results if item["status"] == "clean")

    ai_result = run_ai_model_placeholder({"text": user_text, "files": file_results, "urls": url_results})
    elapsed_ms = int((time.time() - started) * 1000)

    response = {
        "status": overall_status,
        "reply": build_reply(overall_status, len(file_results), len(url_results)),
        "scan_id": hashlib.sha1(f"{utc_now_iso()}:{user_text}:{len(file_results)}".encode()).hexdigest()[:10],
        "scanned_at": utc_now_iso(),
        "duration_ms": elapsed_ms,
        "ai_model_status": ai_result["status"],
        "ai_model_enabled": ai_result["enabled"],
        "summary": {
            "total_files": len(file_results),
            "clean_files": clean_count,
            "warning_files": warning_count,
            "malicious_files": malicious_count,
            "total_urls": len(url_results),
            "max_risk_percent": max([item.get("risk_percent", 0) for item in status_items], default=0),
        },
        "results": file_results,
        "text_analysis": text_analysis,
        "recommendations": DANGER_ADVICE if overall_status == "malicious" else (WARNING_ADVICE if overall_status == "warning" else SAFE_ADVICE),
    }
    return jsonify(response)


if __name__ == "__main__":
    port = int(os.getenv("PORT", "5000"))
    app.run(host="0.0.0.0", port=port, debug=os.getenv("FLASK_DEBUG", "0") == "1")
