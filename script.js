/* =============================================
   STAR HEALTH SYSTEM — script.js
   ============================================= */

// ── State ──────────────────────────────────────
let currentUser = { name: "Alex Johnson", email: "alex@example.com" };
let dashChartInstance = null;
let diaryChartInstance = null;
let scoreChartInstance = null;
let currentWeekOffset = 0;
let diaryFilter = 'all';
let chatHistory = [];
let isGenerating = false;

const biomarkerData = {
  labels: ["Mon","Tue","Wed","Thu","Fri","Sat","Sun"],
  hydration: [75, 80, 70, 85, 78, 82, 79],
  glucose:   [90, 95, 88, 92, 100, 97, 94],
  protein:   [10, 11, 14, 12,  13, 12, 11],
  ph:        [7.1, 7.2, 7.0, 7.2, 7.3, 7.1, 7.2]
};

// ── Utilities ──────────────────────────────────
function showToast(msg) {
  let t = document.getElementById("toast");
  if (!t) {
    t = document.createElement("div");
    t.id = "toast";
    document.body.appendChild(t);
  }
  t.textContent = msg;
  t.classList.add("show");
  setTimeout(() => t.classList.remove("show"), 3000);
}

function setUserUI(name, email) {
  const initial = name.charAt(0).toUpperCase();
  ["sidebarAvatar","topbarAvatar","menuAvatar","settingsAvatar"].forEach(id => {
    const el = document.getElementById(id);
    if (el) el.textContent = initial;
  });
  const nameEls = ["sidebarName","menuName"];
  nameEls.forEach(id => { const el = document.getElementById(id); if (el) el.textContent = name; });
  const emailEl = document.getElementById("menuEmail");
  if (emailEl) emailEl.textContent = email;
}

function setDate() {
  const el = document.getElementById("currentDate");
  if (el) {
    const d = new Date();
    el.textContent = d.toLocaleDateString("en-US", { weekday:"short", month:"short", day:"numeric" });
  }
}

// ── Auth (localStorage) ────────────────────────
const USERS_KEY = "star_users";
const SESSION_KEY = "star_session";

function getUsers() {
  try { return JSON.parse(localStorage.getItem(USERS_KEY)) || {}; }
  catch { return {}; }
}

function saveUsers(users) {
  localStorage.setItem(USERS_KEY, JSON.stringify(users));
}

async function hashPassword(password) {
  try {
    if (crypto && crypto.subtle) {
      const data = new TextEncoder().encode(password + "::star::salt");
      const buf = await crypto.subtle.digest("SHA-256", data);
      return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, "0")).join("");
    }
  } catch (e) {}
  // Fallback simple hash (if crypto.subtle unavailable)
  let h1 = 0xdeadbeef, h2 = 0x41c6ce57;
  const str = password + "::star::salt";
  for (let i = 0; i < str.length; i++) {
    const ch = str.charCodeAt(i);
    h1 = Math.imul(h1 ^ ch, 2654435761);
    h2 = Math.imul(h2 ^ ch, 1597334677);
  }
  h1 = Math.imul(h1 ^ (h1 >>> 16), 2246822507) ^ Math.imul(h2 ^ (h2 >>> 13), 3266489909);
  h2 = Math.imul(h2 ^ (h2 >>> 16), 2246822507) ^ Math.imul(h1 ^ (h1 >>> 13), 3266489909);
  return (h2 >>> 0).toString(16).padStart(8, "0") + (h1 >>> 0).toString(16).padStart(8, "0");
}

function normalizeEmail(email) {
  return email.trim().toLowerCase();
}

function isValidEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

function showAuthError(containerId, message) {
  const el = document.getElementById(containerId);
  if (el) {
    el.textContent = message;
    el.style.display = "block";
  }
}

function clearAuthError(containerId) {
  const el = document.getElementById(containerId);
  if (el) el.style.display = "none";
}

async function handleLogin() {
  clearAuthError("loginError");
  const email = normalizeEmail(document.getElementById("loginEmail").value);
  const password = document.getElementById("loginPassword").value;

  if (!email || !password) {
    showAuthError("loginError", "Please enter both email and password.");
    return;
  }

  const users = getUsers();
  const user = users[email];

  if (!user) {
    showAuthError("loginError", "No account found with this email. Please create an account first.");
    return;
  }

  const hash = await hashPassword(password);
  if (hash !== user.passwordHash) {
    showAuthError("loginError", "Incorrect password. Please try again.");
    return;
  }

  currentUser = { name: user.name, email: user.email };
  localStorage.setItem(SESSION_KEY, JSON.stringify(currentUser));
  enterApp();
}

async function handleRegister() {
  clearAuthError("registerError");
  const name = document.getElementById("regName").value.trim();
  const email = normalizeEmail(document.getElementById("regEmail").value);
  const password = document.getElementById("regPassword").value;

  if (!name || !email || !password) {
    showAuthError("registerError", "Please fill in all fields.");
    return;
  }

  if (!isValidEmail(email)) {
    showAuthError("registerError", "Please enter a valid email address.");
    return;
  }

  if (password.length < 6) {
    showAuthError("registerError", "Password is too weak. Use at least 6 characters.");
    return;
  }

  const users = getUsers();
  if (users[email]) {
    showAuthError("registerError", "An account with this email already exists. Try signing in.");
    return;
  }

  const passwordHash = await hashPassword(password);
  users[email] = { name, email, passwordHash, createdAt: new Date().toISOString() };
  saveUsers(users);

  currentUser = { name, email };
  localStorage.setItem(SESSION_KEY, JSON.stringify(currentUser));
  showToast("Account created. Welcome!");
  enterApp();
}

function enterApp() {
  document.getElementById("auth").style.display = "none";
  document.getElementById("app").style.display = "flex";
  setUserUI(currentUser.name, currentUser.email);
  setDate();
  loadAIConfig();
  loadFirebaseSettings();
  setTimeout(() => {
    renderDashboardChart();
    renderScoreChart();
    renderDiaryChart();
    initFirebase();
  }, 100);
}

function showRegister() {
  clearAuthError("loginError");
  document.getElementById("loginCard").style.display = "none";
  document.getElementById("registerCard").style.display = "block";
}

function showLogin() {
  clearAuthError("registerError");
  document.getElementById("loginCard").style.display = "block";
  document.getElementById("registerCard").style.display = "none";
}

function logout() {
  localStorage.removeItem(SESSION_KEY);
  location.reload();
}

// ── Session Persistence (remember login) ───────
function initAuthState() {
  const raw = localStorage.getItem(SESSION_KEY);
  if (!raw) return;
  try {
    const session = JSON.parse(raw);
    if (session && session.email) {
      currentUser = { name: session.name, email: session.email };
      enterApp();
    }
  } catch (e) {}
}

// ── Navigation ─────────────────────────────────
const pageTitles = {
  dashboard: ["Dashboard", "Overview of your health metrics"],
  analysis: ["Sample Analysis", "AI-powered condition detection from sample images"],
  diary: ["Health Diary", "Track and review your daily biomarkers"],
  ai: ["AI Assistant", "Get personalized health insights"],
  community: ["Community", "Connect with other health enthusiasts"],
  settings: ["Settings", "Manage your account and preferences"]
};

function showPage(page, el) {
  document.querySelectorAll(".page").forEach(p => p.style.display = "none");
  const target = document.getElementById(page);
  if (target) { target.style.display = "block"; target.style.animation = "none"; void target.offsetWidth; target.style.animation = ""; }

  const [title, subtitle] = pageTitles[page] || [page, ""];
  document.getElementById("pageTitle").textContent = title;
  const sub = document.getElementById("pageSubtitle");
  if (sub) sub.textContent = subtitle;

  document.querySelectorAll(".nav-item").forEach(n => n.classList.remove("active"));
  if (el) {
    el.classList.add("active");
  } else {
    const match = document.querySelector(`.nav-item[data-page="${page}"]`);
    if (match) match.classList.add("active");
  }

  // Close profile menu
  const menu = document.getElementById("profileMenu");
  if (menu) menu.style.display = "none";
}

function toggleProfile() {
  const menu = document.getElementById("profileMenu");
  menu.style.display = menu.style.display === "block" ? "none" : "block";
}

document.addEventListener("click", (e) => {
  const wrapper = document.querySelector(".profile-wrapper");
  const menu = document.getElementById("profileMenu");
  if (wrapper && menu && !wrapper.contains(e.target)) {
    menu.style.display = "none";
  }
});

// ── Dashboard Charts ───────────────────────────
function renderDashboardChart(type = "line") {
  const ctx = document.getElementById("dashboardChart");
  if (!ctx) return;
  if (dashChartInstance) { dashChartInstance.destroy(); }

  const isDark = document.body.classList.contains("dark");
  const gridColor = isDark ? "rgba(255,255,255,0.06)" : "rgba(0,0,0,0.05)";
  const tickColor = isDark ? "#8a8a8a" : "#94a3b8";

  dashChartInstance = new Chart(ctx, {
    type,
    data: {
      labels: biomarkerData.labels,
      datasets: [
        { label: "Hydration %", data: biomarkerData.hydration, borderColor: "#0891b2", backgroundColor: type === "bar" ? "rgba(8,145,178,0.7)" : "rgba(8,145,178,0.1)", fill: type !== "bar", tension: 0.4, pointBackgroundColor: "#0891b2", pointRadius: type === "bar" ? 0 : 4, borderWidth: 2 },
        { label: "Glucose mg/dL", data: biomarkerData.glucose, borderColor: "#10b981", backgroundColor: type === "bar" ? "rgba(16,185,129,0.7)" : "rgba(16,185,129,0.1)", fill: type !== "bar", tension: 0.4, pointBackgroundColor: "#10b981", pointRadius: type === "bar" ? 0 : 4, borderWidth: 2 },
        { label: "Protein mg/dL", data: biomarkerData.protein, borderColor: "#f59e0b", backgroundColor: type === "bar" ? "rgba(245,158,11,0.7)" : "rgba(245,158,11,0.1)", fill: type !== "bar", tension: 0.4, pointBackgroundColor: "#f59e0b", pointRadius: type === "bar" ? 0 : 4, borderWidth: 2 },
        { label: "pH", data: biomarkerData.ph, borderColor: "#8b5cf6", backgroundColor: type === "bar" ? "rgba(139,92,246,0.7)" : "rgba(139,92,246,0.1)", fill: type !== "bar", tension: 0.4, pointBackgroundColor: "#8b5cf6", pointRadius: type === "bar" ? 0 : 4, borderWidth: 2 }
      ]
    },
    options: {
      responsive: true,
      interaction: { mode: "index", intersect: false },
      plugins: {
        legend: { position: "top", labels: { color: tickColor, boxWidth: 12, padding: 16, font: { family: "'DM Sans', sans-serif", size: 12 } } },
        tooltip: { backgroundColor: isDark ? "#1a1a1a" : "white", titleColor: isDark ? "#f5f5f5" : "#1a2332", bodyColor: isDark ? "#a1a1a1" : "#5a6a80", borderColor: isDark ? "#333333" : "#e4eaf2", borderWidth: 1, padding: 12, cornerRadius: 10, boxPadding: 4 }
      },
      scales: {
        x: { grid: { color: gridColor }, ticks: { color: tickColor, font: { family: "'DM Sans', sans-serif" } } },
        y: { grid: { color: gridColor }, ticks: { color: tickColor, font: { family: "'DM Sans', sans-serif" } } }
      }
    }
  });
}

function switchDashChart(type, btn) {
  document.querySelectorAll(".chart-btn").forEach(b => b.classList.remove("active"));
  btn.classList.add("active");
  renderDashboardChart(type);
}

function renderScoreChart() {
  const ctx = document.getElementById("scoreChart");
  if (!ctx) return;
  if (scoreChartInstance) scoreChartInstance.destroy();

  scoreChartInstance = new Chart(ctx, {
    type: "doughnut",
    data: {
      datasets: [{
        data: [87, 13],
        backgroundColor: ["#00c97b", "rgba(128,128,128,0.18)"],
        borderWidth: 0,
        hoverOffset: 0
      }]
    },
    options: {
      cutout: "78%",
      plugins: { legend: { display: false }, tooltip: { enabled: false } },
      animation: { duration: 1000, easing: "easeOutQuart" }
    }
  });
}

// ── Diary ──────────────────────────────────────
function renderDiaryChart(filter = "all") {
  const ctx = document.getElementById("biomarkerChart");
  if (!ctx) return;
  if (diaryChartInstance) { diaryChartInstance.destroy(); }

  const isDark = document.body.classList.contains("dark");
  const gridColor = isDark ? "rgba(255,255,255,0.06)" : "rgba(0,0,0,0.05)";
  const tickColor = isDark ? "#8a8a8a" : "#94a3b8";

  const allDatasets = [
    { label: "Hydration %", data: biomarkerData.hydration, borderColor: "#0891b2", backgroundColor: "rgba(8,145,178,0.1)", key: "hydration" },
    { label: "Glucose mg/dL", data: biomarkerData.glucose, borderColor: "#10b981", backgroundColor: "rgba(16,185,129,0.1)", key: "glucose" },
    { label: "Protein mg/dL", data: biomarkerData.protein, borderColor: "#f59e0b", backgroundColor: "rgba(245,158,11,0.1)", key: "protein" },
    { label: "pH", data: biomarkerData.ph, borderColor: "#8b5cf6", backgroundColor: "rgba(139,92,246,0.1)", key: "ph" }
  ];

  const datasets = filter === "all"
    ? allDatasets
    : allDatasets.filter(d => d.key === filter);

  diaryChartInstance = new Chart(ctx, {
    type: "line",
    data: {
      labels: biomarkerData.labels,
      datasets: datasets.map(d => ({
        ...d,
        fill: true,
        tension: 0.4,
        pointBackgroundColor: d.borderColor,
        pointRadius: 5,
        pointHoverRadius: 7,
        borderWidth: 2.5
      }))
    },
    options: {
      responsive: true,
      interaction: { mode: "index", intersect: false },
      plugins: {
        legend: { position: "top", labels: { color: tickColor, boxWidth: 12, padding: 16, font: { family: "'DM Sans', sans-serif", size: 12 } } },
        tooltip: { backgroundColor: isDark ? "#1a1a1a" : "white", titleColor: isDark ? "#f5f5f5" : "#1a2332", bodyColor: isDark ? "#a1a1a1" : "#5a6a80", borderColor: isDark ? "#333333" : "#e4eaf2", borderWidth: 1, padding: 12, cornerRadius: 10 }
      },
      scales: {
        x: { grid: { color: gridColor }, ticks: { color: tickColor, font: { family: "'DM Sans', sans-serif" } } },
        y: { grid: { color: gridColor }, ticks: { color: tickColor, font: { family: "'DM Sans', sans-serif" } } }
      }
    }
  });
}

function filterDiary(filter, btn) {
  diaryFilter = filter;
  document.querySelectorAll(".metric-btn").forEach(b => b.classList.remove("active"));
  btn.classList.add("active");
  renderDiaryChart(filter);
}

function changeWeek(dir) {
  currentWeekOffset += dir;
  const el = document.getElementById("weekLabel");
  if (el) {
    if (currentWeekOffset === 0) el.textContent = "This Week";
    else if (currentWeekOffset === -1) el.textContent = "Last Week";
    else if (currentWeekOffset > 0) el.textContent = `${currentWeekOffset} week${currentWeekOffset > 1 ? "s" : ""} ahead`;
    else el.textContent = `${Math.abs(currentWeekOffset)} weeks ago`;
  }
}

// ── Diary Log Modal ─────────────────────────────
function openLogModal() {
  document.getElementById("logModal").style.display = "flex";
}

function closeLogModal() {
  document.getElementById("logModal").style.display = "none";
}

function saveLogEntry() {
  const hydration = document.getElementById("logHydration").value;
  const glucose = document.getElementById("logGlucose").value;
  const protein = document.getElementById("logProtein").value;
  const ph = document.getElementById("logPH").value;
  const note = document.getElementById("logNote").value;

  if (!hydration && !glucose && !protein && !ph) {
    showToast("Please enter at least one value.");
    return;
  }

  const today = new Date();
  const dayNames = ["Sun","Mon","Tue","Wed","Thu","Fri","Sat"];
  const dayName = dayNames[today.getDay()];
  const dayNum = today.getDate();

  const entry = document.createElement("div");
  entry.className = "diary-entry";
  entry.innerHTML = `
    <div class="entry-day"><span class="day-name">${dayName}</span><span class="day-num">${dayNum}</span></div>
    <div class="entry-metrics">
      ${hydration ? `<div class="entry-metric blue"><span>Hydration</span><strong>${hydration}%</strong></div>` : ""}
      ${glucose ? `<div class="entry-metric green"><span>Glucose</span><strong>${glucose} mg/dL</strong></div>` : ""}
      ${protein ? `<div class="entry-metric orange"><span>Protein</span><strong>${protein} mg/dL</strong></div>` : ""}
      ${ph ? `<div class="entry-metric purple"><span>pH</span><strong>${ph}</strong></div>` : ""}
    </div>
    <div class="entry-note">${note || "No notes added."}</div>
    <div class="entry-status good">Logged</div>
  `;

  const container = document.getElementById("diaryEntries");
  container.insertBefore(entry, container.firstChild);

  // Clear
  ["logHydration","logGlucose","logProtein","logPH","logNote"].forEach(id => {
    const el = document.getElementById(id);
    if (el) el.value = "";
  });

  closeLogModal();
  showToast("Entry saved successfully");
}

// ── AI Chat (Groq / Llama 3) ───────────────────
function getApiKey() {
  return localStorage.getItem("star_groq_key") || "";
}

function getAIModel() {
  const m = localStorage.getItem("star_groq_model");
  if (!m || m === "llama-3.3-70b-versatile" || m === "llama-3.1-8b-instant" || m === "llama-3.2-3b-preview") return "openai/gpt-oss-20b";
  return m;
}

function getSystemPrompt() {
  const d = biomarkerData;
  const latest = {
    hydration: d.hydration[d.hydration.length - 1],
    glucose: d.glucose[d.glucose.length - 1],
    protein: d.protein[d.protein.length - 1],
    ph: d.ph[d.ph.length - 1]
  };
  return `You are STAR, a friendly and knowledgeable AI health assistant embedded in the STAR Health System dashboard. You help users understand their biomarkers, give health advice, and answer health-related questions.

Current user's biomarker data (this week):
- Hydration: ${d.hydration.join(", ")}% (avg: ${(d.hydration.reduce((a,b)=>a+b,0)/d.hydration.length).toFixed(0)}%, latest: ${latest.hydration}%)
- Glucose: ${d.glucose.join(", ")} mg/dL (avg: ${(d.glucose.reduce((a,b)=>a+b,0)/d.glucose.length).toFixed(0)} mg/dL, latest: ${latest.glucose} mg/dL)
- Protein: ${d.protein.join(", ")} mg/dL (avg: ${(d.protein.reduce((a,b)=>a+b,0)/d.protein.length).toFixed(0)} mg/dL, latest: ${latest.protein} mg/dL)
- pH Level: ${d.ph.join(", ")} (avg: ${(d.ph.reduce((a,b)=>a+b,0)/d.ph.length).toFixed(1)}, latest: ${latest.ph})

User name: ${currentUser.name}

Guidelines:
- Be concise but warm.
- Reference the user's actual data when relevant.
- For medical emergencies, always advise seeing a doctor.
- You can suggest diet, exercise, and lifestyle changes based on biomarkers.
- Keep responses under 3-4 sentences unless more detail is requested.
- Do not diagnose conditions. Frame everything as general wellness advice.`;
}

function quickPrompt(text) {
  const input = document.getElementById("chatInput");
  if (input) {
    input.value = text;
    sendMessage();
  }
}

function handleChatKey(e) {
  if (e.key === "Enter" && !e.shiftKey) {
    e.preventDefault();
    sendMessage();
  }
}

async function sendMessage() {
  const input = document.getElementById("chatInput");
  const chatBox = document.getElementById("chatBox");
  if (!input || !chatBox) return;
  if (!input.value.trim() || isGenerating) return;

  const apiKey = getApiKey();
  if (!apiKey) {
    showToast("Please set your Groq API key in Settings > AI Assistant");
    return;
  }

  const text = input.value.trim();
  input.value = "";
  isGenerating = true;

  // User message
  const userMsg = document.createElement("div");
  userMsg.className = "chat-message user";
  userMsg.innerHTML = `
    <div class="msg-avatar">${currentUser.name.charAt(0)}</div>
    <div class="msg-bubble">${escapeHtml(text)}</div>
  `;
  chatBox.appendChild(userMsg);
  chatBox.scrollTop = chatBox.scrollHeight;

  // Add to history
  chatHistory.push({ role: "user", content: text });

  // Typing indicator
  const typingWrap = document.createElement("div");
  typingWrap.className = "chat-message ai";
  typingWrap.innerHTML = `
    <div class="msg-avatar">AI</div>
    <div class="typing-indicator">
      <div class="typing-dot"></div><div class="typing-dot"></div><div class="typing-dot"></div>
    </div>
  `;
  chatBox.appendChild(typingWrap);
  chatBox.scrollTop = chatBox.scrollHeight;

  try {
    const response = await fetch("https://api.groq.com/openai/v1/chat/completions", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Authorization": `Bearer ${apiKey}`
      },
      body: JSON.stringify({
        model: getAIModel(),
        messages: [
          { role: "system", content: getSystemPrompt() },
          ...chatHistory.slice(-20)
        ],
        temperature: 0.7,
        max_tokens: 500
      })
    });

    if (!response.ok) {
      const err = await response.json().catch(() => ({}));
      throw new Error(err.error?.message || `API error ${response.status}`);
    }

    const data = await response.json();
    const reply = data.choices?.[0]?.message?.content || "No response received.";

    chatHistory.push({ role: "assistant", content: reply });

    typingWrap.remove();
    const botMsg = document.createElement("div");
    botMsg.className = "chat-message ai";
    botMsg.innerHTML = `
      <div class="msg-avatar">AI</div>
      <div class="msg-bubble">${escapeHtml(reply).replace(/\n/g, "<br>")}</div>
    `;
    chatBox.appendChild(botMsg);
    chatBox.scrollTop = chatBox.scrollHeight;

  } catch (err) {
    typingWrap.remove();
    const errMsg = document.createElement("div");
    errMsg.className = "chat-message ai";
    errMsg.innerHTML = `
      <div class="msg-avatar">AI</div>
      <div class="msg-bubble" style="border-color:var(--red);">Error: ${escapeHtml(err.message)}</div>
    `;
    chatBox.appendChild(errMsg);
    chatBox.scrollTop = chatBox.scrollHeight;
    chatHistory.pop();
  } finally {
    isGenerating = false;
  }
}

function escapeHtml(str) {
  return str.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}

// ── ML Analysis Engine (StarVision — fully offline) ──
// Reads the actual pixels of the uploaded image and classifies it into one
// of four stool types. Runs entirely in the browser - no server, no API key.
const StarVision = (() => {
  const TYPE_DEFS = {
    1: {
      type: 1, name: 'Type 1 - Normal', label: 'Normal',
      classification: 'Healthy Stool', color: 'brown',
      texture: 'solid, smooth', shape: 'well formed',
      bristol: 'Type 4 (sausage-like)', risk: 'LOW', riskScore: 20,
      icon: '✅', hydration: 82,
      conditions: ['Normal bowel movement', 'No major abnormalities detected'],
      recommendations: [
        'Maintain hydration by drinking 2.5-3L of water daily.',
        'Continue a balanced diet rich in fibre, fruits and vegetables.',
        'Maintain consistent physical activity and healthy habits.',
      ],
    },
    2: {
      type: 2, name: 'Type 2 - Loose Motion', label: 'Loose Motion',
      classification: 'Loose Stool', color: 'pale / yellow / greenish',
      texture: 'semi-liquid, soft', shape: 'loose, unformed',
      bristol: 'Type 6-7 (soft / watery)', risk: 'MEDIUM', riskScore: 50,
      icon: '💧', hydration: 60,
      conditions: ['Mild gastroenteritis', 'Dietary sensitivity', 'Possible infection'],
      recommendations: [
        'Drink plenty of fluids to avoid dehydration.',
        'Consume ORS (oral rehydration solution) if frequency is high.',
        'Eat bland, easy-to-digest foods like rice, bananas and toast.',
        'Consult a doctor if loose motion persists beyond 48 hours.',
      ],
    },
    3: {
      type: 3, name: 'Type 3 - Tight Solid', label: 'Constipation',
      classification: 'Constipated Stool', color: 'dark brown',
      texture: 'hard, dry, compact', shape: 'lumpy, pellet-like',
      bristol: 'Type 1-2 (hard lumps)', risk: 'MEDIUM', riskScore: 45,
      icon: '🪨', hydration: 45,
      conditions: ['Constipation', 'Low fibre intake', 'Reduced hydration'],
      recommendations: [
        'Increase daily water intake significantly.',
        'Add fibre-rich foods: whole grains, fruits, vegetables, legumes.',
        'Incorporate regular physical activity.',
        'Consider a mild stool softener or laxative after consulting a doctor.',
      ],
    },
    4: {
      type: 4, name: 'Type 4 - High Risk', label: 'High Risk',
      classification: 'High-Risk Gastrointestinal Pattern',
      color: 'black / red', texture: 'tarry / bloody', shape: 'irregular',
      bristol: 'N/A - Abnormal', risk: 'HIGH', riskScore: 90,
      icon: '⚠️', hydration: 35,
      conditions: [
        'Gastrointestinal bleeding (black/tarry stool)',
        'Blood in stool (bright red / maroon)',
        'Possible colorectal disease - immediate review required',
      ],
      recommendations: [
        'Seek medical consultation immediately.',
        'Do not self-medicate with stool softeners or laxatives.',
        'Collect a fresh sample for laboratory testing if advised.',
        'Provide your doctor with a complete symptom history.',
        'If dizziness, severe pain or weakness occur, visit emergency care.',
      ],
    },
  };
  const DISCLAIMER = 'This AI analysis is for educational and research purposes only and is not a medical diagnosis. Consult a qualified medical professional for proper evaluation.';

  const analyzeFile = (file) => new Promise((resolve, reject) => {
    const url = URL.createObjectURL(file);
    const img = new Image();
    img.onload = () => {
      try {
        const canvas = document.createElement('canvas');
        const MAX = 320;
        const scale = Math.min(1, MAX / Math.max(img.width, img.height));
        canvas.width = Math.max(1, Math.round(img.width * scale));
        canvas.height = Math.max(1, Math.round(img.height * scale));
        const ctx = canvas.getContext('2d', { willReadFrequently: true });
        ctx.drawImage(img, 0, 0, canvas.width, canvas.height);
        const pixels = ctx.getImageData(0, 0, canvas.width, canvas.height);
        const stats = computeColorStats(pixels);
        const analysis = classify(stats);
        const report = buildReport(analysis, stats, file);
        report.thumbnail = canvas.toDataURL('image/jpeg', 0.6);
        URL.revokeObjectURL(url);
        resolve(report);
      } catch (e) {
        URL.revokeObjectURL(url);
        reject(e);
      }
    };
    img.onerror = () => { URL.revokeObjectURL(url); reject(new Error('Could not load image')); };
    img.src = url;
  });

  const computeColorStats = (imageData) => {
    const d = imageData.data;
    const len = d.length;
    const counts = { total: 0, brown: 0, darkBrown: 0, black: 0, red: 0, maroon: 0, pale: 0, yellowGreen: 0, white: 0 };
    let sumR = 0, sumG = 0, sumB = 0;
    for (let i = 0; i < len; i += 4) {
      const r = d[i], g = d[i + 1], b = d[i + 2], a = d[i + 3];
      if (a < 100) continue;
      const lum = 0.299 * r + 0.587 * g + 0.114 * b;
      if (lum > 235) { counts.white++; continue; }
      counts.total++;
      sumR += r; sumG += g; sumB += b;
      if (isRed(r, g, b)) counts.red++;
      else if (isMaroon(r, g, b)) counts.maroon++;
      else if (isBlack(r, g, b)) counts.black++;
      else if (isDarkBrown(r, g, b)) counts.darkBrown++;
      else if (isBrown(r, g, b)) counts.brown++;
      else if (isYellowGreen(r, g, b)) counts.yellowGreen++;
      else if (isPale(r, g, b)) counts.pale++;
    }
    const total = counts.total || 1;
    const pct = (n) => Number(((n / total) * 100).toFixed(1));
    return { ...counts, total, whitePct: pct(counts.white),
      pct: { brown: pct(counts.brown), darkBrown: pct(counts.darkBrown), black: pct(counts.black), red: pct(counts.red), maroon: pct(counts.maroon), pale: pct(counts.pale), yellowGreen: pct(counts.yellowGreen) },
      avgLum: (sumR + sumG + sumB) / (3 * total) };
  };

  const isRed = (r, g, b) => r > 140 && r - g > 50 && r - b > 50 && g < 130;
  const isMaroon = (r, g, b) => r > 90 && g < 65 && b < 65 && r - g > 45 && r > g * 1.8;
  const isBlack = (r, g, b) => r < 60 && g < 60 && b < 60;
  const isDarkBrown = (r, g, b) => {
    const lum = 0.299 * r + 0.587 * g + 0.114 * b;
    return (r >= 55 && r < 150 && g >= 35 && g < 110 && b < 80 &&
      r >= g && g >= b && r - b > 15 && r < g * 1.8 && lum < 100);
  };
  const isBrown = (r, g, b) => r >= 130 && g >= 90 && b < 125 && r >= g && g >= b && r - b > 20 && r < g * 1.7;
  const isYellowGreen = (r, g, b) => {
    const lum = 0.299 * r + 0.587 * g + 0.114 * b;
    const yellow = r >= g && g >= b && b > 100 && (r - b) > 20 && lum > 130;
    const green = g > r && g >= b && g > 110 && lum > 130;
    return yellow || green;
  };
  const isPale = (r, g, b) => {
    const max = Math.max(r, g, b), min = Math.min(r, g, b);
    const lum = 0.299 * r + 0.587 * g + 0.114 * b;
    return lum > 205 && max - min < 55;
  };

  const classify = (stats) => {
    const p = stats.pct;
    const riskSignals = p.red + p.maroon + p.black;
    if (riskSignals >= 12 || (p.red >= 6 && p.black >= 4)) return { type: 4, confidence: scoreConfidence(riskSignals, 40) };
    if (p.black >= 18) return { type: 4, confidence: scoreConfidence(p.black, 25) };
    const liquidSignals = p.yellowGreen + p.pale;
    if (liquidSignals >= 35 && p.brown + p.darkBrown < 30 && p.black + p.red < 8) return { type: 2, confidence: scoreConfidence(liquidSignals, 45) };
    if (p.darkBrown >= 32 && p.yellowGreen + p.pale < 18) return { type: 3, confidence: scoreConfidence(p.darkBrown, 40) };
    if (p.brown + p.darkBrown >= 40) return { type: 1, confidence: scoreConfidence(p.brown + p.darkBrown, 55) };
    if (p.darkBrown >= 20) return { type: 3, confidence: scoreConfidence(p.darkBrown, 60) };
    if (liquidSignals >= 20) return { type: 2, confidence: scoreConfidence(liquidSignals, 60) };
    return { type: 1, confidence: 62 };
  };

  const scoreConfidence = (signal, base) => Math.max(55, Math.min(96, Math.round(base + signal * 0.6)));

  const buildReport = (analysis, stats, file) => {
    const def = TYPE_DEFS[analysis.type];
    return {
      id: 'STAR-' + Date.now().toString(36).toUpperCase(),
      type: analysis.type, typeName: def.name, label: def.label,
      classification: def.classification, color: def.color,
      texture: def.texture, shape: def.shape, bristol: def.bristol,
      risk: def.risk, riskScore: def.riskScore, confidence: analysis.confidence,
      hydration: def.hydration, icon: def.icon, conditions: def.conditions,
      recommendations: def.recommendations, disclaimer: DISCLAIMER,
      colorBreakdown: stats.pct,
      date: new Date().toISOString(),
      dateLabel: new Date().toLocaleString('en-GB', { day: '2-digit', month: 'short', year: 'numeric', hour: '2-digit', minute: '2-digit' }),
      fileName: file ? file.name : 'unknown',
    };
  };

  return { analyzeFile, TYPE_DEFS, DISCLAIMER, computeColorStats, classify };
})();

let uploadedImageData = null;
let uploadedFile = null;
let lastAnalysisResult = null;
let postImageData = null;

function handleDragOver(e) {
  e.preventDefault();
  document.getElementById("uploadZone").classList.add("dragover");
}

function handleDragLeave(e) {
  e.preventDefault();
  document.getElementById("uploadZone").classList.remove("dragover");
}

function handleDrop(e) {
  e.preventDefault();
  document.getElementById("uploadZone").classList.remove("dragover");
  const file = e.dataTransfer.files[0];
  if (file && file.type.startsWith("image/")) processFile(file);
}

function handleFileSelect(input) {
  if (input.files[0]) processFile(input.files[0]);
}

function processFile(file) {
  uploadedFile = file;
  const reader = new FileReader();
  reader.onload = e => {
    uploadedImageData = e.target.result;
    document.getElementById("previewImg").src = uploadedImageData;
    document.getElementById("imagePreviewCard").style.display = "block";
    document.getElementById("placeholderCard").style.display = "none";
  };
  reader.readAsDataURL(file);
}

function resetAnalysis() {
  uploadedImageData = null;
  uploadedFile = null;
  document.getElementById("imagePreviewCard").style.display = "none";
  document.getElementById("analysisResult").style.display = "none";
  document.getElementById("aiThinking").style.display = "none";
  document.getElementById("placeholderCard").style.display = "block";
  document.getElementById("fileInput").value = "";
}

async function runAIAnalysis() {
  if (!uploadedFile) return;

  document.getElementById("analysisResult").style.display = "none";
  document.getElementById("placeholderCard").style.display = "none";
  document.getElementById("aiThinking").style.display = "block";
  document.getElementById("analyzeBtn").disabled = true;

  try {
    const [report] = await Promise.all([
      StarVision.analyzeFile(uploadedFile),
      new Promise(res => setTimeout(res, 1400))
    ]);
    lastAnalysisResult = report;
    showAnalysisResult(report);
  } catch (err) {
    showToast("Analysis failed: " + err.message);
    document.getElementById("placeholderCard").style.display = "block";
  } finally {
    document.getElementById("aiThinking").style.display = "none";
    document.getElementById("analyzeBtn").disabled = false;
  }
}

function showAnalysisResult(r) {
  const header = document.getElementById("resultHeader");
  const classes = { low: "normal", medium: "warning", high: "danger" };
  const severity = (r.risk || "low").toLowerCase();

  header.className = "result-header " + (classes[severity] || "normal");
  document.getElementById("resultIcon").textContent = r.icon || "🔬";
  document.getElementById("resultTitle").textContent = `${r.label} — ${r.classification}`;
  document.getElementById("resultSubtitle").textContent = (r.conditions && r.conditions[0]) || r.typeName;

  const conf = Math.min(99, Math.max(55, Number(r.confidence) || 70));
  document.getElementById("confidenceText").textContent = conf + "% confidence";
  setTimeout(() => { document.getElementById("confidenceBar").style.width = conf + "%"; }, 100);

  const iconsList = ["✅", "💧", "🏃", "🩺"];
  document.getElementById("recList").innerHTML = (r.recommendations || []).map((rec, i) => `
    <div class="rec-item"><div class="rec-icon">${iconsList[i % iconsList.length]}</div><div class="rec-text">${escapeHtml(rec)}</div></div>
  `).join("");

  const meta = document.getElementById("resultMeta");
  if (meta) {
    meta.textContent = `${r.typeName} · Bristol: ${r.bristol} · Color: ${r.color} · Texture: ${r.texture}`;
    meta.style.display = "block";
  }
  const disc = document.getElementById("resultDisclaimer");
  if (disc) {
    disc.textContent = r.disclaimer || "";
    disc.style.display = "block";
  }

  document.getElementById("analysisResult").style.display = "block";
}

function downloadReport() {
  if (!lastAnalysisResult) return;
  const r = lastAnalysisResult;
  const text = `STAR HEALTH ASSESSMENT REPORT
Report ID: ${r.id}
Generated: ${r.dateLabel}

CLASSIFICATION: ${r.label} — ${r.classification}
TYPE: ${r.typeName}
RISK LEVEL: ${r.risk}
CONFIDENCE: ${r.confidence}%
HYDRATION ESTIMATE: ${r.hydration}%

SAMPLE PROFILE:
Color: ${r.color}
Texture: ${r.texture}
Shape: ${r.shape}
Bristol Scale: ${r.bristol}

POSSIBLE CONDITIONS:
${(r.conditions || []).map(c => "- " + c).join("\n")}

RECOMMENDATIONS:
${(r.recommendations || []).map((c, i) => `${i + 1}. ${c}`).join("\n")}

---
${r.disclaimer || ""}`;

  const blob = new Blob([text], { type: "text/plain" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `STAR-Report-${r.id}.txt`;
  a.click();
  URL.revokeObjectURL(url);
}

// ── Settings ────────────────────────────────────
function switchSettings(section, el) {
  document.querySelectorAll(".settings-section").forEach(s => s.style.display = "none");
  document.querySelectorAll(".settings-nav-item").forEach(n => n.classList.remove("active"));
  const target = document.getElementById(`settings-${section}`);
  if (target) target.style.display = "block";
  if (el) el.classList.add("active");
}

function saveProfile() {
  const name = document.getElementById("settingsName").value;
  const email = document.getElementById("settingsEmail").value;
  if (name) {
    currentUser = { name, email };
    setUserUI(name, email);
    showToast("Profile saved");
  }
}

function saveAIConfig() {
  const key = document.getElementById("groqApiKey").value.trim();
  const model = document.getElementById("groqModel").value;
  const status = document.getElementById("aiConfigStatus");

  if (!key) {
    status.style.color = "var(--red)";
    status.textContent = "Please enter an API key.";
    return;
  }

  localStorage.setItem("star_groq_key", key);
  localStorage.setItem("star_groq_model", model);
  status.style.color = "var(--green)";
  status.textContent = "Settings saved. API key is stored in your browser.";
  showToast("AI settings saved");
}

function loadAIConfig() {
  const key = localStorage.getItem("star_groq_key") || "";
  const m = localStorage.getItem("star_groq_model");
  const model = (!m || m === "llama-3.3-70b-versatile" || m === "llama-3.1-8b-instant" || m === "llama-3.2-3b-preview")
    ? "openai/gpt-oss-20b"
    : m;
  const keyInput = document.getElementById("groqApiKey");
  const modelSelect = document.getElementById("groqModel");
  if (keyInput) keyInput.value = key;
  if (modelSelect) modelSelect.value = model;
}

function toggleSwitch(el) {
  el.classList.toggle("on");
}

function setTheme(theme, card) {
  document.querySelectorAll(".theme-card").forEach(c => c.classList.remove("active"));
  card.classList.add("active");
  if (theme === "dark") {
    document.body.classList.add("dark");
    showToast("Dark mode enabled");
  } else {
    document.body.classList.remove("dark");
    showToast("Light mode enabled");
  }
  // Re-render charts to update colors
  setTimeout(() => {
    renderDashboardChart();
    renderDiaryChart(diaryFilter);
    renderScoreChart();
  }, 100);
}

// ── Community (Firebase) ────────────────────────
let db = null;
let unsubscribePosts = null;
let communityFilter = "all";

const avatarColors = ["#4f9ef8","#27c38f","#f4a035","#8b5cf6","#ef4444","#ec4899","#14b8a6","#f97316"];

function getAvatarColor(name) {
  let hash = 0;
  for (let i = 0; i < name.length; i++) hash = name.charCodeAt(i) + ((hash << 5) - hash);
  return avatarColors[Math.abs(hash) % avatarColors.length];
}

function timeAgo(timestamp) {
  if (!timestamp) return "just now";
  const seconds = Math.floor((Date.now() - timestamp.toMillis()) / 1000);
  if (seconds < 60) return "just now";
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return minutes + "m ago";
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return hours + "h ago";
  const days = Math.floor(hours / 24);
  return days + "d ago";
}

function saveFirebaseConfig() {
  const config = {
    apiKey: document.getElementById("fbApiKey").value.trim(),
    authDomain: document.getElementById("fbAuthDomain").value.trim(),
    projectId: document.getElementById("fbProjectId").value.trim(),
    storageBucket: document.getElementById("fbStorageBucket").value.trim(),
    messagingSenderId: document.getElementById("fbMessagingSenderId").value.trim(),
    appId: document.getElementById("fbAppId").value.trim()
  };
  const status = document.getElementById("fbConfigStatus");

  if (!config.apiKey || !config.projectId) {
    status.style.color = "var(--red)";
    status.textContent = "API Key and Project ID are required.";
    return;
  }

  localStorage.setItem("star_firebase_config", JSON.stringify(config));
  status.style.color = "var(--green)";
  status.textContent = "Firebase connected! Reloading...";
  showToast("Community connected");
  setTimeout(() => location.reload(), 1000);
}

function loadFirebaseConfig() {
  const raw = localStorage.getItem("star_firebase_config");
  if (raw) {
    try { return JSON.parse(raw); } catch {}
  }
  return {
    apiKey: "AIzaSyAmjuBhgJE0dsytOjpPSvGrySZgqIThEt4",
    authDomain: "musicon-cfe95.firebaseapp.com",
    projectId: "musicon-cfe95",
    storageBucket: "musicon-cfe95.firebasestorage.app",
    messagingSenderId: "487117999956",
    appId: "1:487117999956:web:886a94ec11ce17b87302c1"
  };
}

function loadFirebaseSettings() {
  const config = loadFirebaseConfig();
  if (!config) return;
  const fields = { apiKey: "fbApiKey", authDomain: "fbAuthDomain", projectId: "fbProjectId", storageBucket: "fbStorageBucket", messagingSenderId: "fbMessagingSenderId", appId: "fbAppId" };
  for (const [key, id] of Object.entries(fields)) {
    const el = document.getElementById(id);
    if (el) el.value = config[key] || "";
  }
}

async function initFirebase() {
  const config = loadFirebaseConfig();
  if (!config || !window.firebaseModules) {
    const s = document.getElementById("communityStatus");
    if (s) s.innerHTML = "Connect Firebase in <strong>Settings &gt; Community</strong> to enable the community.";
    return;
  }

  try {
    const { getFirestore } = window.firebaseModules;
    if (!window._fbApp) {
      const { initializeApp } = window.firebaseModules;
      window._fbApp = initializeApp(config);
    }
    if (!window._fbAuth) {
      const { getAuth } = window.firebaseModules;
      window._fbAuth = getAuth(window._fbApp);
    }
    db = getFirestore(window._fbApp);
    listenToPosts();
  } catch (err) {
    const s = document.getElementById("communityStatus");
    if (s) s.textContent = "Firebase connection failed: " + err.message;
  }
}

function listenToPosts() {
  if (!db || !window.firebaseModules) return;
  if (unsubscribePosts) { unsubscribePosts(); unsubscribePosts = null; }
  const { collection, onSnapshot, query, orderBy } = window.firebaseModules;
  const forumPosts = document.getElementById("forumPosts");
  const status = document.getElementById("communityStatus");

  let allPosts = [];

  const q = query(collection(db, "posts"), orderBy("createdAt", "desc"));
  unsubscribePosts = onSnapshot(q, (snapshot) => {
    allPosts = [];
    let totalLikes = 0;
    const users = new Set();

    snapshot.forEach(doc => {
      const p = { id: doc.id, ...doc.data() };
      allPosts.push(p);
      totalLikes += (p.likes || []).length;
      users.add(p.authorName);
    });

    document.getElementById("statPosts").textContent = allPosts.length;
    document.getElementById("statLikes").textContent = totalLikes;
    document.getElementById("statMembers").textContent = users.size;

    renderPosts(allPosts);
  });
}

function renderPosts(posts) {
  const container = document.getElementById("forumPosts");
  if (!container) return;

  const filtered = communityFilter === "all"
    ? posts
    : posts.filter(p => p.category === communityFilter);

  if (filtered.length === 0) {
    container.innerHTML = '<div style="text-align:center;padding:40px;color:var(--text-3);font-size:0.9rem;">No posts yet. Be the first to post!</div>';
    return;
  }

  container.innerHTML = filtered.map(p => {
    const initial = (p.authorName || "U").charAt(0).toUpperCase();
    const color = getAvatarColor(p.authorName || "User");
    const liked = (p.likes || []).includes(currentUser.name);
    const catTag = p.category && p.category !== "general"
      ? `<span class="post-tag ${p.category}">${p.category.replace("-", " ")}</span>`
      : "";

    return `
      <div class="forum-post" data-id="${p.id}">
        <div class="post-avatar" style="background:${color}">${initial}</div>
        <div class="post-body">
          <div class="post-header">
            <strong>${escapeHtml(p.authorName || "User")}</strong>
            ${catTag}
            <span class="post-time">${timeAgo(p.createdAt)}</span>
            ${p.authorName === currentUser.name ? `
              <span class="post-actions">
                <button onclick="editPost('${p.id}', this)" title="Edit">✏️</button>
                <button onclick="deletePost('${p.id}')" title="Delete">🗑️</button>
              </span>` : ""}
          </div>
          <p id="postText-${p.id}">${escapeHtml(p.text || "")}</p>
          ${p.image ? `<img src="${escapeHtml(p.image)}" style="max-width:100%;max-height:280px;border-radius:10px;object-fit:cover;margin-top:8px;" alt="post image">` : ""}
          <div class="post-footer">
            <button onclick="toggleComments('${p.id}')">💬 ${(p.commentCount || 0)}</button>
            <button onclick="toggleLike('${p.id}', ${JSON.stringify(p.likes || [])})" style="${liked ? "color:var(--red);border-color:var(--red)" : ""}">❤ ${(p.likes || []).length}</button>
          </div>
          <div class="comments-section" id="comments-${p.id}" style="display:none;">
            <div class="comments-list" id="commentsList-${p.id}"></div>
            <div class="comment-input-row">
              <input type="text" id="commentInput-${p.id}" placeholder="Write a comment..." onkeydown="if(event.key==='Enter')postComment('${p.id}')">
              <button class="btn-primary small" onclick="postComment('${p.id}')">Reply</button>
            </div>
          </div>
        </div>
      </div>`;
  }).join("");
}

function handlePostImage(input) {
  const file = input.files[0];
  if (!file) return;
  const reader = new FileReader();
  reader.onload = e => {
    postImageData = e.target.result;
    document.getElementById("postPreviewImg").src = postImageData;
    document.getElementById("postImagePreview").style.display = "block";
  };
  reader.readAsDataURL(file);
  input.value = "";
}

function removePostImage() {
  postImageData = null;
  document.getElementById("postImagePreview").style.display = "none";
  document.getElementById("postImageInput").value = "";
}

async function createPost() {
  if (!db || !window.firebaseModules) {
    showToast("Connect Firebase in Settings first");
    return;
  }
  const { addDoc, collection, serverTimestamp } = window.firebaseModules;
  const text = document.getElementById("newPostText").value.trim();
  const category = document.getElementById("newPostCategory").value;

  if (!text) { showToast("Write something first"); return; }

  try {
    await addDoc(collection(db, "posts"), {
      authorName: currentUser.name,
      text: text,
      category: category,
      likes: [],
      commentCount: 0,
      image: postImageData || null,
      createdAt: serverTimestamp()
    });
    document.getElementById("newPostText").value = "";
    postImageData = null;
    document.getElementById("postImagePreview").style.display = "none";
    showToast("Post published");
  } catch (err) {
    showToast("Error: " + err.message);
  }
}

function editPost(postId, btn) {
  const el = document.getElementById("postText-" + postId);
  if (!el) return;
  const oldText = el.textContent;
  const wrapper = el.parentElement.querySelector('.post-editing');
  if (!wrapper) {
    const parser = new DOMParser();
    const html = `
      <div class="post-editing" style="margin:8px 0;">
        <textarea id="editPostText-${postId}" rows="2" style="width:100%;">${escapeHtml(oldText)}</textarea>
        <button class="btn-primary small" onclick="savePostEdit('${postId}')">Save</button>
        <button class="btn-ghost small" onclick="cancelPostEdit('${postId}')">Cancel</button>
      </div>`;
    el.insertAdjacentHTML('afterend', html);
  }
}

async function savePostEdit(postId) {
  const el = document.getElementById("editPostText-" + postId);
  if (!el) return;
  const text = el.value.trim();
  if (!text) return;
  if (!db || !window.firebaseModules) return;
  const { doc, updateDoc } = window.firebaseModules;
  try {
    await updateDoc(doc(db, "posts", postId), { text: text });
    const txtEl = document.getElementById("postText-" + postId);
    if (txtEl) txtEl.textContent = text;
    const editor = txtEl.parentElement.querySelector('.post-editing');
    if (editor) editor.remove();
    showToast("Post updated");
  } catch (err) {
    showToast("Error: " + err.message);
  }
}

function cancelPostEdit(postId) {
  const txtEl = document.getElementById("postText-" + postId);
  if (txtEl) {
    const editor = txtEl.parentElement.querySelector('.post-editing');
    if (editor) editor.remove();
  }
}

async function deletePost(postId) {
  if (!db || !window.firebaseModules) return;
  if (!confirm("Delete this post?")) return;
  const { deleteDoc, doc, getDocs, collection } = window.firebaseModules;
  try {
    const snap = await getDocs(collection(db, "posts", postId, "comments"));
    for (const c of snap.docs) await deleteDoc(c.ref);
    await deleteDoc(doc(db, "posts", postId));
    showToast("Post deleted");
  } catch (err) {
    showToast("Error: " + err.message);
  }
}

async function toggleLike(postId, currentLikes) {
  if (!db || !window.firebaseModules) return;
  const { doc, updateDoc, arrayUnion, arrayRemove } = window.firebaseModules;
  const ref = doc(db, "posts", postId);
  const name = currentUser.name;

  try {
    if (currentLikes.includes(name)) {
      await updateDoc(ref, { likes: arrayRemove(name) });
    } else {
      await updateDoc(ref, { likes: arrayUnion(name) });
    }
  } catch (err) {
    showToast("Error: " + err.message);
  }
}

function toggleComments(postId) {
  const el = document.getElementById("comments-" + postId);
  if (!el) return;
  const isHidden = el.style.display === "none";
  el.style.display = isHidden ? "block" : "none";
  if (isHidden) loadComments(postId);
}

async function loadComments(postId) {
  if (!db || !window.firebaseModules) return;
  const { collection, getDocs, query, orderBy } = window.firebaseModules;
  const list = document.getElementById("commentsList-" + postId);
  if (!list) return;

  try {
    const snap = await getDocs(query(collection(db, "posts", postId, "comments"), orderBy("createdAt", "asc")));
    if (snap.empty) {
      list.innerHTML = '<p style="font-size:0.8rem;color:var(--text-3);padding:8px 0;">No comments yet.</p>';
      return;
    }
    list.innerHTML = snap.docs.map(d => {
      const c = d.data();
      const cid = d.id;
      const initial = (c.authorName || "U").charAt(0).toUpperCase();
      const color = getAvatarColor(c.authorName || "User");
      return `
        <div class="comment-item" id="commentItem-${cid}">
          <div class="comment-avatar" style="background:${color}">${initial}</div>
          <div class="comment-body">
            <strong>${escapeHtml(c.authorName || "User")}</strong>
            <p id="commentText-${cid}">${escapeHtml(c.text || "")}</p>
            <span class="comment-time">${timeAgo(c.createdAt)}</span>
            ${c.authorName === currentUser.name ? `
              <span class="comment-actions">
                <button onclick="editComment('${postId}','${cid}')" title="Edit">✏️</button>
                <button onclick="deleteComment('${postId}','${cid}')" title="Delete">🗑️</button>
              </span>` : ""}
          </div>
        </div>`;
    }).join("");
  } catch (err) {
    list.innerHTML = '<p style="font-size:0.8rem;color:var(--red);">Failed to load comments</p>';
  }
}

function editComment(postId, commentId) {
  const el = document.getElementById("commentText-" + commentId);
  if (!el) return;
  const oldText = el.textContent;
  const parser = new DOMParser();
  const html = `
    <div class="comment-editing" style="margin:6px 0;">
      <textarea id="editCommentText-${commentId}" rows="2" style="width:100%;">${escapeHtml(oldText)}</textarea>
      <button class="btn-primary small" onclick="saveCommentEdit('${postId}','${commentId}')">Save</button>
      <button class="btn-ghost small" onclick="cancelCommentEdit('${commentId}')">Cancel</button>
    </div>`;
  el.insertAdjacentHTML('afterend', html);
}

async function saveCommentEdit(postId, commentId) {
  const el = document.getElementById("editCommentText-" + commentId);
  if (!el) return;
  const text = el.value.trim();
  if (!text) return;
  if (!db || !window.firebaseModules) return;
  const { doc, updateDoc } = window.firebaseModules;
  try {
    await updateDoc(doc(db, "posts", postId, "comments", commentId), { text: text });
    const txtEl = document.getElementById("commentText-" + commentId);
    if (txtEl) txtEl.textContent = text;
    const editor = txtEl.parentElement.querySelector('.comment-editing');
    if (editor) editor.remove();
    showToast("Comment updated");
  } catch (err) {
    showToast("Error: " + err.message);
  }
}

function cancelCommentEdit(commentId) {
  const txtEl = document.getElementById("commentText-" + commentId);
  if (txtEl) {
    const editor = txtEl.parentElement.querySelector('.comment-editing');
    if (editor) editor.remove();
  }
}

async function deleteComment(postId, commentId) {
  if (!db || !window.firebaseModules) return;
  if (!confirm("Delete this comment?")) return;
  const { deleteDoc, doc, updateDoc, increment } = window.firebaseModules;
  try {
    await deleteDoc(doc(db, "posts", postId, "comments", commentId));
    await updateDoc(doc(db, "posts", postId), { commentCount: increment(-1) });
    const item = document.getElementById("commentItem-" + commentId);
    if (item) item.remove();
    showToast("Comment deleted");
  } catch (err) {
    showToast("Error: " + err.message);
  }
}

async function postComment(postId) {
  if (!db || !window.firebaseModules) return;
  const { addDoc, collection, doc, updateDoc, serverTimestamp, increment } = window.firebaseModules;
  const input = document.getElementById("commentInput-" + postId);
  if (!input) return;
  const text = input.value.trim();
  if (!text) return;

  try {
    await addDoc(collection(db, "posts", postId, "comments"), {
      authorName: currentUser.name,
      text: text,
      createdAt: serverTimestamp()
    });
    await updateDoc(doc(db, "posts", postId), { commentCount: increment(1) });
    input.value = "";
    loadComments(postId);
  } catch (err) {
    showToast("Error: " + err.message);
  }
}

function filterCommunity(cat, btn) {
  communityFilter = cat;
  document.querySelectorAll(".forum-cat").forEach(b => b.classList.remove("active"));
  btn.classList.add("active");
  listenToPosts();
}

document.addEventListener("DOMContentLoaded", () => {
  loadFirebaseSettings();
  initAuthState();
  initFirebase();
  const av = document.getElementById("communityAvatar");
  if (av) av.textContent = currentUser.name.charAt(0).toUpperCase();
});

// ── Intro Splash ────────────────────────────────
function skipIntro() {
  const intro = document.getElementById("intro");
  if (!intro) return;
  intro.classList.add("hide");
  setTimeout(() => intro.remove(), 700);
}

setTimeout(skipIntro, 3400);