"use strict";

const API_BASE_URL = (window.SHIELDME_API_URL || "http://127.0.0.1:5000").replace(/\/$/, "");
const REQUIRE_AUTH = Boolean(window.SHIELDME_REQUIRE_AUTH);
const MAX_CLIENT_FILE_SIZE = 10 * 1024 * 1024;
const MAX_CLIENT_FILE_COUNT = 8;
const HISTORY_KEY_PREFIX = "shieldme_scan_history_v3";

const state = {
    currentPage: "home",
    currentUser: null,
    serviceOnline: false,
    navigating: false,
};

function $(id) {
    return document.getElementById(id);
}

function showToast(title, icon = "info", timer = 3000) {
    if (window.Swal) {
        Swal.fire({
            toast: true,
            position: "top-end",
            icon,
            title,
            showConfirmButton: false,
            timer,
            timerProgressBar: true,
            background: "#0d1117",
            color: "#fff",
            iconColor: icon === "success" ? "#00e5ff" : icon === "error" ? "#ff4b2b" : "#ffa500",
        });
    } else {
        console.log(`${icon}: ${title}`);
    }
}
window.showToast = showToast;

function createElement(tag, className = "", text = "") {
    const element = document.createElement(tag);
    if (className) element.className = className;
    if (text) element.textContent = text;
    return element;
}

function clearChildren(element) {
    if (!element) return;
    while (element.firstChild) element.removeChild(element.firstChild);
}

function formatTime(value) {
    try {
        return new Intl.DateTimeFormat("ar-EG", {
            dateStyle: "short",
            timeStyle: "short",
        }).format(new Date(value));
    } catch {
        return value || "الآن";
    }
}

function statusLabel(status) {
    const labels = {
        malicious: "خطر",
        critical: "حرج",
        high: "مرتفع",
        warning: "تحذير",
        medium: "متوسط",
        low: "منخفض",
        clean: "آمن مبدئيًا",
        info: "معلومة",
        error: "خطأ",
    };
    return labels[status] || status || "غير معروف";
}

function statusClass(status) {
    const danger = ["malicious", "critical", "high", "error"];
    const warning = ["warning", "medium", "low"];
    if (danger.includes(status)) return "is-danger";
    if (warning.includes(status)) return "is-warning";
    if (status === "clean") return "is-clean";
    return "is-info";
}

function statusIcon(status) {
    if (["malicious", "critical", "high", "error"].includes(status)) return "🚨";
    if (["warning", "medium", "low"].includes(status)) return "⚠️";
    if (status === "clean") return "✅";
    return "ℹ️";
}

function toggleMenu() {
    const links = $("nav-links");
    if (links) links.classList.toggle("open");
}
window.toggleMenu = toggleMenu;

function closeMenu() {
    const links = $("nav-links");
    if (links) links.classList.remove("open");
}

function activatePage(pageId) {
    document.querySelectorAll(".page").forEach((page) => page.classList.remove("active"));
    const target = $(pageId);
    if (target) target.classList.add("active");
    state.currentPage = pageId;
    closeMenu();

    if (pageId === "quiz") startQuiz();
    if (pageId === "history") renderHistory();
    window.scrollTo({ top: 0, behavior: "smooth" });
}

function showPage(pageId) {
    const loader = $("global-loader");
    const fill = $("fill-bar");
    const count = $("pc-count");
    const lock = document.querySelector(".lock-icon");

    if (!loader || state.navigating) {
        activatePage(pageId);
        return;
    }

    state.navigating = true;
    loader.style.display = "flex";
    loader.setAttribute("aria-hidden", "false");
    if (fill) fill.style.width = "0%";
    if (count) count.textContent = "0";
    if (lock) lock.textContent = "🔒";

    let progress = 0;
    const interval = setInterval(() => {
        progress += Math.floor(Math.random() * 20) + 14;
        if (progress >= 100) {
            progress = 100;
            clearInterval(interval);
            if (lock) lock.textContent = "🔓";
            setTimeout(() => {
                activatePage(pageId);
                loader.style.display = "none";
                loader.setAttribute("aria-hidden", "true");
                if (fill) fill.style.width = "0%";
                state.navigating = false;
            }, 180);
        }
        if (fill) fill.style.width = `${progress}%`;
        if (count) count.textContent = String(progress);
    }, 60);
}
window.showPage = showPage;

function focusScanner() {
    showPage("home");
    setTimeout(() => $("user-input")?.focus(), 450);
}
window.focusScanner = focusScanner;

function toggleAuth(forceRegister) {
    const loginForm = $("login-form");
    const registerForm = $("register-form");
    if (!loginForm || !registerForm) return;

    const shouldShowRegister = typeof forceRegister === "boolean" ? forceRegister : registerForm.hidden;
    registerForm.hidden = !shouldShowRegister;
    loginForm.hidden = shouldShowRegister;
}
window.toggleAuth = toggleAuth;

function setAuthUser(user) {
    state.currentUser = user;
    const loginItem = $("login-item-nav");
    const logoutItem = $("logout-item-nav");
    if (loginItem) loginItem.hidden = Boolean(user);
    if (logoutItem) logoutItem.hidden = !user;
    updateAuthGate();
    if (state.currentPage === "history") renderHistory();
}
window.setAuthUser = setAuthUser;

function updateAuthGate() {
    const gate = $("auth-gate");
    const form = $("scan-form");
    if (!gate || !form) return;

    const locked = REQUIRE_AUTH && !state.currentUser;
    gate.hidden = !locked;
    form.classList.toggle("is-locked", locked);
    form.querySelectorAll("input, button, label").forEach((element) => {
        if (element.id !== "attach-label") element.disabled = locked;
    });
}

async function checkServiceHealth() {
    const pill = $("service-status");
    if (!pill) return;

    try {
        const response = await fetch(`${API_BASE_URL}/health`, { cache: "no-store" });
        if (!response.ok) throw new Error(`status ${response.status}`);
        await response.json();
        state.serviceOnline = true;
        pill.textContent = "الخدمة متصلة";
        pill.className = "service-pill online";
    } catch (error) {
        state.serviceOnline = false;
        pill.textContent = "الخدمة غير متصلة";
        pill.className = "service-pill offline";
        console.warn("Service health check failed:", error);
    }
}

function updateFileName() {
    const fileInput = $("file-input");
    const attachLabel = $("attach-label");
    const fileCount = $("file-count");
    if (!fileInput || !attachLabel || !fileCount) return;

    const files = Array.from(fileInput.files || []);
    if (!files.length) {
        attachLabel.textContent = "📎";
        attachLabel.classList.remove("has-files");
        fileCount.textContent = "لا توجد ملفات مرفقة";
        return;
    }

    attachLabel.textContent = "📁";
    attachLabel.classList.add("has-files");
    const names = files.map((file) => file.name).join("، ");
    fileCount.textContent = `${files.length} ملف: ${names.length > 80 ? `${names.slice(0, 80)}...` : names}`;
}
window.updateFileName = updateFileName;

function validateFiles(files) {
    if (files.length > MAX_CLIENT_FILE_COUNT) {
        return `الحد الأقصى ${MAX_CLIENT_FILE_COUNT} ملفات في الطلب الواحد.`;
    }
    const largeFile = files.find((file) => file.size > MAX_CLIENT_FILE_SIZE);
    if (largeFile) {
        return `الملف "${largeFile.name}" أكبر من 10MB.`;
    }
    return "";
}

function setLoading(isLoading) {
    const input = $("user-input");
    const fileInput = $("file-input");
    const btn = $("send-btn");
    const loader = $("loader");

    if (input) input.disabled = isLoading;
    if (fileInput) fileInput.disabled = isLoading;
    if (btn) {
        btn.disabled = isLoading;
        btn.textContent = isLoading ? "جاري الفحص..." : "فحص";
    }
    if (loader) loader.hidden = !isLoading;
}

function ensureResultArea() {
    const box = $("chat-box");
    if (!box) return null;
    const empty = box.querySelector(".empty-state");
    if (empty) empty.remove();
    return box;
}

function addUserSubmission(message, files) {
    const box = ensureResultArea();
    if (!box) return;

    const bubble = createElement("div", "user-submission");
    const title = createElement("strong", "", "طلب الفحص");
    bubble.appendChild(title);

    if (message) bubble.appendChild(createElement("p", "", message));
    if (files.length) {
        const fileLine = createElement("p", "", `الملفات: ${files.map((file) => file.name).join("، ")}`);
        bubble.appendChild(fileLine);
    }
    box.appendChild(bubble);
    box.scrollTop = box.scrollHeight;
}

function riskMeter(percent) {
    const wrapper = createElement("div", "risk-meter");
    const bar = createElement("span", "");
    bar.style.width = `${Math.max(4, Number(percent) || 0)}%`;
    wrapper.appendChild(bar);
    return wrapper;
}

function indicatorList(items) {
    const list = createElement("ul", "indicator-list");
    items.forEach((item) => {
        const li = createElement("li");
        const title = createElement("strong", "", item.title || item.rule || "مؤشر");
        const text = createElement("span", "", ` — ${item.description || "تم العثور على مؤشر يحتاج مراجعة."}`);
        li.append(title, text);
        list.appendChild(li);
    });
    return list;
}

function adviceList(items) {
    const list = createElement("ul", "advice-list");
    items.slice(0, 4).forEach((advice) => list.appendChild(createElement("li", "", advice)));
    return list;
}

function renderItemCard(item) {
    const status = item.status || item.risk_level || "info";
    const card = createElement("article", `scan-item-card ${statusClass(status)}`);

    const header = createElement("div", "item-header");
    const titleText = item.type === "url" ? item.host || item.url : item.filename || "نتيجة الفحص";
    const title = createElement("h4", "", `${statusIcon(status)} ${titleText}`);
    const badge = createElement("span", `status-badge ${statusClass(status)}`, statusLabel(status));
    header.append(title, badge);
    card.appendChild(header);

    const meta = createElement("div", "item-meta");
    if (item.type === "file") {
        meta.appendChild(createElement("span", "", `الحجم: ${item.size_label || "غير معروف"}`));
        if (item.hash_preview) meta.appendChild(createElement("span", "", `بصمة: ${item.hash_preview}`));
    } else if (item.type === "url") {
        meta.appendChild(createElement("span", "", item.url || ""));
    }
    meta.appendChild(createElement("span", "", `درجة الخطورة: ${item.risk_percent || 0}%`));
    card.appendChild(meta);

    card.appendChild(riskMeter(item.risk_percent || 0));
    card.appendChild(createElement("p", "item-message", item.message || "تم الفحص."));

    const indicators = item.indicators || item.matches || [];
    if (indicators.length) {
        card.appendChild(createElement("h5", "mini-title", "أسباب النتيجة"));
        card.appendChild(indicatorList(indicators));
    }

    if (Array.isArray(item.advice) && item.advice.length) {
        card.appendChild(createElement("h5", "mini-title", "نصائح مقترحة"));
        card.appendChild(adviceList(item.advice));
    }

    return card;
}

function renderScanResponse(data) {
    const box = ensureResultArea();
    if (!box) return;

    const status = data.status || "info";
    const wrapper = createElement("section", `scan-result-card ${statusClass(status)}`);

    const top = createElement("div", "result-top");
    const left = createElement("div", "");
    left.appendChild(createElement("span", "eyebrow", "نتيجة الفحص"));
    left.appendChild(createElement("h3", "", `${statusIcon(status)} ${data.reply || "تم الفحص"}`));
    const badge = createElement("span", `status-badge ${statusClass(status)}`, statusLabel(status));
    top.append(left, badge);
    wrapper.appendChild(top);

    const summary = data.summary || {};
    const counters = createElement("div", "result-counters");
    [
        ["الملفات", summary.total_files || 0],
        ["الروابط", summary.total_urls || 0],
        ["نظيفة", summary.clean_files || 0],
        ["تحذيرات", summary.warning_files || 0],
        ["خطرة", summary.malicious_files || 0],
    ].forEach(([label, value]) => {
        const item = createElement("span", "counter-pill", `${label}: ${value}`);
        counters.appendChild(item);
    });
    counters.appendChild(createElement("span", "counter-pill", `وقت الفحص: ${data.duration_ms || 0}ms`));
    wrapper.appendChild(counters);

    const maxRisk = Number(summary.max_risk_percent || 0);
    const riskLine = createElement("div", "overall-risk");
    riskLine.appendChild(createElement("span", "", `أعلى درجة خطورة: ${maxRisk}%`));
    riskLine.appendChild(riskMeter(maxRisk));
    wrapper.appendChild(riskLine);

    if (data.text_analysis) {
        wrapper.appendChild(renderItemCard({ ...data.text_analysis, type: "text", filename: "تحليل النص" }));
        if (Array.isArray(data.text_analysis.urls)) {
            data.text_analysis.urls.forEach((urlItem) => wrapper.appendChild(renderItemCard(urlItem)));
        }
    }

    if (Array.isArray(data.results)) {
        data.results.forEach((fileItem) => wrapper.appendChild(renderItemCard(fileItem)));
    }

    if (Array.isArray(data.recommendations) && data.recommendations.length) {
        const rec = createElement("div", "recommendation-box");
        rec.appendChild(createElement("h4", "", "توصيات عامة"));
        rec.appendChild(adviceList(data.recommendations));
        wrapper.appendChild(rec);
    }

    box.appendChild(wrapper);
    box.scrollTop = box.scrollHeight;
    saveHistory(data);
}

function clearResults() {
    const box = $("chat-box");
    if (!box) return;
    clearChildren(box);
    const empty = createElement("div", "empty-state");
    empty.appendChild(createElement("div", "empty-icon", "🛡️"));
    empty.appendChild(createElement("h3", "", "جاهز للفحص"));
    empty.appendChild(createElement("p", "", "ارفع ملفًا أو أرسل رابطًا، وستظهر النتيجة هنا."));
    box.appendChild(empty);
}
window.clearResults = clearResults;

async function sendMessage(event) {
    if (event) event.preventDefault();

    if (REQUIRE_AUTH && !state.currentUser) {
        showToast("سجّل الدخول أولاً لاستخدام الفحص", "warning");
        showPage("login");
        return;
    }

    const input = $("user-input");
    const fileInput = $("file-input");
    if (!input || !fileInput) return;

    const message = input.value.trim();
    const files = Array.from(fileInput.files || []);
    if (!message && !files.length) return showToast("اكتب رابطًا أو ارفع ملفًا أولاً", "warning");

    const fileError = validateFiles(files);
    if (fileError) return showToast(fileError, "warning", 4500);

    const formData = new FormData();
    if (message) formData.append("text", message);
    files.forEach((file) => formData.append("file", file));

    addUserSubmission(message, files);
    setLoading(true);

    try {
        const response = await fetch(`${API_BASE_URL}/scan`, {
            method: "POST",
            body: formData,
        });
        const data = await response.json().catch(() => ({}));
        if (!response.ok) throw new Error(data.message || `Server error ${response.status}`);
        renderScanResponse(data);
        input.value = "";
        fileInput.value = "";
        updateFileName();
    } catch (error) {
        console.error("Connection Error:", error);
        renderScanResponse({
            status: "error",
            reply: "تعذر الاتصال بخدمة الفحص. تأكد من تشغيل الخادم ثم حاول مرة أخرى.",
            duration_ms: 0,
            summary: { total_files: 0, total_urls: 0, clean_files: 0, warning_files: 0, malicious_files: 0, max_risk_percent: 0 },
            recommendations: ["تأكد من أن Backend يعمل على المنفذ 5000.", "افتح الموقع من http://127.0.0.1:5500 وليس من file://."],
        });
    } finally {
        setLoading(false);
    }
}
window.sendMessage = sendMessage;

function getCurrentHistoryKey() {
    if (!state.currentUser) return null;
    const identity = state.currentUser.uid || state.currentUser.email || "unknown";
    return `${HISTORY_KEY_PREFIX}_${identity}`;
}

function getHistory() {
    const key = getCurrentHistoryKey();
    if (!key) return [];
    try {
        return JSON.parse(localStorage.getItem(key) || "[]");
    } catch {
        return [];
    }
}

function saveHistory(data) {
    if (!state.currentUser) return;
    const key = getCurrentHistoryKey();
    if (!key) return;

    const history = getHistory();
    const summary = data.summary || {};
    const item = {
        id: data.scan_id || String(Date.now()),
        status: data.status || "info",
        reply: data.reply || "تم الفحص",
        scanned_at: data.scanned_at || new Date().toISOString(),
        total_files: summary.total_files || 0,
        total_urls: summary.total_urls || 0,
        max_risk_percent: summary.max_risk_percent || 0,
        user: state.currentUser.email || state.currentUser.uid || "user",
    };
    history.unshift(item);
    localStorage.setItem(key, JSON.stringify(history.slice(0, 30)));
}

function renderLoginRequiredHistory(list) {
    const gate = createElement("div", "empty-state");
    gate.appendChild(createElement("div", "empty-icon", "🔒"));
    gate.appendChild(createElement("h3", "", "سجل الفحص متاح للحسابات المسجلة فقط"));
    gate.appendChild(createElement("p", "", "سجّل الدخول حتى يظهر لك سجل عمليات الفحص الخاصة بحسابك فقط."));
    const btn = createElement("button", "secondary-btn", "تسجيل الدخول");
    btn.type = "button";
    btn.onclick = () => showPage("login");
    gate.appendChild(btn);
    list.appendChild(gate);
}

function renderHistory() {
    const list = $("history-list");
    if (!list) return;
    clearChildren(list);

    if (!state.currentUser) {
        renderLoginRequiredHistory(list);
        return;
    }

    const history = getHistory();
    if (!history.length) {
        const empty = createElement("div", "empty-state");
        empty.appendChild(createElement("div", "empty-icon", "📭"));
        empty.appendChild(createElement("h3", "", "لا يوجد سجل بعد"));
        empty.appendChild(createElement("p", "", "ابدأ فحص ملف أو رابط بعد تسجيل الدخول، وسيظهر ملخص العملية هنا."));
        list.appendChild(empty);
        return;
    }

    history.forEach((item) => {
        const card = createElement("article", `history-card ${statusClass(item.status)}`);
        const header = createElement("div", "history-card-head");
        header.appendChild(createElement("strong", "", `${statusIcon(item.status)} ${statusLabel(item.status)}`));
        header.appendChild(createElement("span", "", formatTime(item.scanned_at)));
        card.appendChild(header);
        card.appendChild(createElement("p", "", item.reply));
        const meta = createElement("div", "item-meta");
        meta.appendChild(createElement("span", "", `ملفات: ${item.total_files}`));
        meta.appendChild(createElement("span", "", `روابط: ${item.total_urls}`));
        meta.appendChild(createElement("span", "", `خطورة: ${item.max_risk_percent}%`));
        card.appendChild(meta);
        list.appendChild(card);
    });
}

function clearHistory() {
    if (!state.currentUser) {
        showToast("سجّل الدخول أولاً لإدارة سجل الفحص", "warning");
        showPage("login");
        return;
    }
    const key = getCurrentHistoryKey();
    if (key) localStorage.removeItem(key);
    renderHistory();
    showToast("تم مسح سجل الفحص الخاص بحسابك", "success");
}
window.clearHistory = clearHistory;

const allQuestions = [
    { q: "ما هو التصيد الاحتيالي؟", options: ["محاولة سرقة بياناتك برسائل أو صفحات مزيفة", "تحديث نظام التشغيل", "نوع من الشاشات"], correct: 0 },
    { q: "أي كلمة مرور أقوى؟", options: ["123456", "password", "A@7k9!pW2L"], correct: 2 },
    { q: "ماذا تفعل إذا وصلتك رسالة تطلب رقم حسابك لأنك ربحت جائزة؟", options: ["أرسل البيانات", "أتجاهل الرسالة وأتحقق من المصدر", "أضغط كل الروابط"], correct: 1 },
    { q: "ما فائدة المصادقة الثنائية؟", options: ["خطوة حماية إضافية بعد كلمة المرور", "تسريع الإنترنت", "زيادة مساحة التخزين"], correct: 0 },
    { q: "ما التصرف الأفضل مع ملف مرفق من مصدر مجهول؟", options: ["فتحه فورًا", "فحصه قبل فتحه", "إرساله للجميع"], correct: 1 },
    { q: "ماذا يعني HTTPS؟", options: ["اتصال مشفر بينك وبين الموقع", "موقع مجاني", "سرعة أعلى دائمًا"], correct: 0 },
    { q: "لماذا لا تستخدم نفس كلمة المرور لكل الحسابات؟", options: ["لأن اختراق حساب واحد قد يكشف الباقي", "لأنها صعبة التذكر فقط", "لأن المواقع تمنع ذلك دائمًا"], correct: 0 },
    { q: "ما معنى الهندسة الاجتماعية؟", options: ["خداع المستخدم نفسيًا للحصول على معلومات", "تصميم واجهات", "تقوية المعالج"], correct: 0 },
    { q: "ما الخطر في الروابط المختصرة؟", options: ["قد تخفي الوجهة الحقيقية", "لا تعمل على الهاتف", "تجعل الشاشة أغمق"], correct: 0 },
    { q: "ما التصرف الصحيح عند ظهور تحذير من المتصفح؟", options: ["تجاهله دائمًا", "قراءة التحذير والتأكد قبل المتابعة", "إغلاق الجهاز"], correct: 1 },
    { q: "ما المقصود ببرمجيات الفدية؟", options: ["برامج تشفر ملفاتك وتطلب مقابلًا", "برامج صور", "تحديثات رسمية"], correct: 0 },
    { q: "أي ممارسة تقلل مخاطر الاختراق؟", options: ["تحديث البرامج", "فتح كل المرفقات", "مشاركة كلمة المرور"], correct: 0 },
    { q: "ما أفضل تعامل مع Wi-Fi عام؟", options: ["تجنب الحسابات الحساسة أو استخدام حماية مناسبة", "إرسال كلمات المرور", "إلغاء التحديثات"], correct: 0 },
    { q: "ماذا تفعل إذا شككت أن جهازك مصاب؟", options: ["أعزله عن الشبكة وأفحصه", "أرسل الملفات للكل", "أتجاهل الأمر"], correct: 0 },
    { q: "ما أهمية النسخ الاحتياطي؟", options: ["استعادة الملفات عند التلف أو الهجمات", "زيادة الإضاءة", "تقليل حجم الشاشة"], correct: 0 },
    { q: "ما الخطر من تطبيقات زيادة المتابعين؟", options: ["قد تسرق حسابك", "تغير لون الهاتف", "تمنع الشحن"], correct: 0 },
    { q: "ماذا تعني علامة القفل بجانب الرابط؟", options: ["الاتصال مشفر", "الموقع مضمون 100%", "الحساب مغلق"], correct: 0 },
    { q: "ما الأفضل عند استلام طلب صداقة مجهول؟", options: ["قبوله فورًا", "فحص الحساب والحذر", "إرسال كلمة المرور"], correct: 1 },
    { q: "ما وظيفة جدار الحماية؟", options: ["تقليل الوصول غير المصرح به", "تبريد الجهاز", "تنظيف الشاشة"], correct: 0 },
    { q: "متى تشغل Macro في ملف Office؟", options: ["دائمًا", "فقط عند الثقة الكاملة بالمصدر والحاجة له", "إذا كان اسم الملف جذابًا"], correct: 1 },
];

let currentQuestions = [];
let currentQuestionIndex = 0;
let score = 0;

function shuffle(array) {
    return [...array].sort(() => Math.random() - 0.5);
}

function startQuiz() {
    currentQuestions = shuffle(allQuestions).slice(0, 5);
    currentQuestionIndex = 0;
    score = 0;
    showQuestion();
}

function showQuestion() {
    const qData = currentQuestions[currentQuestionIndex];
    if (!qData) return;
    $("question-text").textContent = qData.q;
    $("question-number").textContent = `السؤال ${currentQuestionIndex + 1} من 5`;
    $("progress").style.width = `${(currentQuestionIndex + 1) * 20}%`;
    $("quiz-feedback").textContent = "";

    const container = $("options-container");
    clearChildren(container);
    qData.options.forEach((option, index) => {
        const btn = createElement("button", "option-btn", option);
        btn.type = "button";
        btn.onclick = () => checkAnswer(index, btn);
        container.appendChild(btn);
    });
}

function checkAnswer(selectedIndex, clickedBtn) {
    const correctIndex = currentQuestions[currentQuestionIndex].correct;
    document.querySelectorAll(".option-btn").forEach((btn) => (btn.disabled = true));
    if (selectedIndex === correctIndex) {
        clickedBtn.classList.add("correct");
        $("quiz-feedback").textContent = "✅ إجابة صحيحة";
        score += 1;
    } else {
        clickedBtn.classList.add("wrong");
        document.querySelectorAll(".option-btn")[correctIndex]?.classList.add("correct");
        $("quiz-feedback").textContent = "❌ إجابة خاطئة";
    }

    setTimeout(() => {
        currentQuestionIndex += 1;
        if (currentQuestionIndex < 5) showQuestion();
        else finishQuiz();
    }, 1000);
}

function finishQuiz() {
    $("question-text").textContent = `انتهى الاختبار! نتيجتك ${score} من 5`;
    const container = $("options-container");
    clearChildren(container);
    const btn = createElement("button", "main-btn", "إعادة الاختبار");
    btn.type = "button";
    btn.onclick = startQuiz;
    container.appendChild(btn);
    $("quiz-feedback").textContent = score >= 4 ? "ممتاز، وعيك الأمني قوي." : "جيد، راجع النصائح وحاول مرة أخرى.";
}

function initParticles() {
    if (typeof particlesJS !== "function") return;
    particlesJS("particles-js", {
        particles: {
            number: { value: window.innerWidth < 600 ? 35 : 70, density: { enable: true, value_area: 800 } },
            color: { value: "#00e5ff" },
            shape: { type: "circle" },
            opacity: { value: 0.45, random: false },
            size: { value: 3, random: true },
            line_linked: { enable: true, distance: 140, color: "#00e5ff", opacity: 0.28, width: 1 },
            move: { enable: true, speed: 1.4, direction: "none", random: false, straight: false, out_mode: "out" },
        },
        interactivity: {
            detect_on: "canvas",
            events: { onhover: { enable: window.innerWidth > 768, mode: "grab" }, onclick: { enable: true, mode: "push" } },
        },
        retina_detect: true,
    });
}

function boot() {
    $("scan-form")?.addEventListener("submit", sendMessage);
    updateAuthGate();
    updateFileName();
    renderHistory();
    initParticles();
    checkServiceHealth();
    setInterval(checkServiceHealth, 30000);
}

document.addEventListener("DOMContentLoaded", boot);
