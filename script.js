/* =============================================
   SWASTHYA HEALTH SYSTEM — script.js
   ============================================= */

// ── State ──────────────────────────────────────
let currentUser = { name: "Alex Johnson", email: "alex@example.com", role: "patient", nmr: "" };
let dashChartInstance = null;
let diaryChartInstance = null;
let scoreChartInstance = null;
let currentWeekOffset = 0;
let diaryFilter = 'all';
let chatHistory = [];
let isGenerating = false;
let currentDoctorSelection = null;

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
const ADMIN_EMAIL = "inventpraveenece2006@gmail.com";

function isAdmin() {
  return currentUser && normalizeEmail(currentUser.email || "") === ADMIN_EMAIL;
}

function getUsers() {
  try { return JSON.parse(localStorage.getItem(USERS_KEY)) || {}; }
  catch { return {}; }
}

function saveUsers(users) {
  localStorage.setItem(USERS_KEY, JSON.stringify(users));
}

const PBKDF2_ITERATIONS = 210000;

function legacyHashPassword(password) {
  try {
    const data = new TextEncoder().encode(password + "::star::salt");
    // synchronous fallback path kept for no-subtle environments via async wrapper below
  } catch (e) {}
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

function bytesToB64(bytes) {
  let bin = "";
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin);
}

function b64ToBytes(b64) {
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

function pbkdf2Hex(password, salt, iterations) {
  const keyPromise = crypto.subtle.importKey("raw", new TextEncoder().encode(password), "PBKDF2", false, ["deriveBits"]);
  return keyPromise.then(key => crypto.subtle.deriveBits({ name: "PBKDF2", salt, iterations, hash: "SHA-256" }, key, 256))
    .then(buf => Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, "0")).join(""));
}

async function hashPassword(password) {
  try {
    if (crypto && crypto.subtle) {
      const salt = crypto.getRandomValues(new Uint8Array(16));
      const hash = await pbkdf2Hex(password, salt, PBKDF2_ITERATIONS);
      return "pbkdf2$" + PBKDF2_ITERATIONS + "$" + bytesToB64(salt) + "$" + hash;
    }
  } catch (e) {}
  return legacyHashPassword(password);
}

async function verifyPassword(password, stored) {
  if (typeof stored === "string" && stored.startsWith("pbkdf2$")) {
    try {
      const parts = stored.split("$");
      if (parts.length !== 4) return false;
      const iter = Number(parts[1]);
      const salt = b64ToBytes(parts[2]);
      const expected = parts[3];
      if (!(iter > 0) || !salt.length || !expected) return false;
      const actual = await pbkdf2Hex(password, salt, iter);
      return actual.toLowerCase() === expected.toLowerCase();
    } catch (e) {
      return false;
    }
  }
  // Legacy SHA-256 hash string (fixed salt)
  if (crypto && crypto.subtle) {
    try {
      const data = new TextEncoder().encode(password + "::star::salt");
      const buf = await crypto.subtle.digest("SHA-256", data);
      const hex = Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, "0")).join("");
      return hex.toLowerCase() === stored.toLowerCase();
    } catch (e) {}
  }
  return legacyHashPassword(password).toLowerCase() === stored.toLowerCase();
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
  const nmr = document.getElementById("loginNmr").value.trim();
  const mode = authMode;

  if (!email || !password) {
    showAuthError("loginError", "Please enter both email and password.");
    return;
  }

  const fb = ensureFirebase();
  if (fb) {
    try {
      const { signInWithEmailAndPassword } = window.firebaseModules;
      const cred = await signInWithEmailAndPassword(fb.auth, email, password);
      let profile = await getSharedProfile(email);
      if (!profile) {
        const local = getUsers()[email];
        if (local) profile = { name: local.name, email: local.email, role: local.role || "patient", nmr: local.nmr || "" };
        if (profile) await upsertSharedProfile(profile);
      }
      if (!profile) profile = { name: (cred.user.displayName || email.split("@")[0]), email, role: "patient", nmr: "" };
      await ensureLegacyRecord(email, profile, password);
      loginAsProfile(profile, mode, nmr);
      return;
    } catch (err) {
      const code = err && err.code ? err.code : "";
      const migrated = await tryLoginLegacy(email, password, mode, nmr);
      if (migrated) return;
      if (code === "auth/email-already-in-use" || code === "auth/invalid-login-credentials" || code === "auth/wrong-password" || code === "auth/invalid-credential" || code === "auth/user-not-found") {
        showAuthError("loginError", "Invalid email or password. If you registered on another device, use the same email and password.");
      } else {
        showAuthError("loginError", (err && err.message) || "Login failed. Check your connection and try again.");
      }
      return;
    }
  }

  await tryLoginLegacy(email, password, mode, nmr);
}

async function tryLoginLegacy(email, password, mode, nmr) {
  const users = getUsers();
  const user = users[email];

  if (!user) {
    showAuthError("loginError", "No account found with this email. Please create an account first.");
    return false;
  }

  const ok = await verifyPassword(password, user.passwordHash);
  if (!ok) {
    showAuthError("loginError", "Incorrect password. Please try again.");
    return false;
  }

  if (typeof user.passwordHash !== "string" || !user.passwordHash.startsWith("pbkdf2$")) {
    user.passwordHash = await hashPassword(password);
    users[email] = user;
    saveUsers(users);
  }
  user.email = user.email || email;

  const profile = { name: user.name, email: user.email, role: user.role || "patient", nmr: user.nmr || "" };

  if (window.firebaseModules && loadFirebaseConfig()) {
    try {
      const fb = ensureFirebase();
      if (fb) {
        const { createUserWithEmailAndPassword, signInWithEmailAndPassword, updateProfile } = window.firebaseModules;
        let cred = null;
        try {
          cred = await signInWithEmailAndPassword(fb.auth, email, password);
        } catch (e) {
          if (e && e.code === "auth/user-not-found") {
            cred = await createUserWithEmailAndPassword(fb.auth, email, password);
            await updateProfile(cred.user, { displayName: profile.name || "" }).catch(() => {});
          } else {
            throw e;
          }
        }
        await upsertSharedProfile(profile);
        await ensureLegacyRecord(email, profile, password);
        loginAsProfile(profile, mode, nmr);
        return true;
      }
    } catch (migErr) {
      // migration to cloud failed; still allow offline/local login below
    }
  }

  loginAsProfile(profile, mode, nmr);
  return true;
}

function loginAsProfile(profile, mode, typedNmr) {
  if (!profile || !profile.role) {
    showAuthError("loginError", "No account found with this email. Please create an account first.");
    return;
  }
  if (profile.role !== mode) {
    showAuthError("loginError", mode === "doctor"
      ? "This account is registered as a patient. Switch to Patient mode."
      : "This account is registered as a doctor. Switch to Doctor mode.");
    return;
  }
  if (mode === "doctor" && (!typedNmr || typedNmr.toUpperCase() !== (profile.nmr || "").toUpperCase())) {
    showAuthError("loginError", "Enter the correct NMR/Registration Number for this doctor account.");
    return;
  }
  currentUser = { name: profile.name, email: profile.email, role: profile.role || "patient", nmr: profile.nmr || "" };
  localStorage.setItem(SESSION_KEY, JSON.stringify(currentUser));
  enterApp();
}

async function ensureLegacyRecord(email, profile, password) {
  const users = getUsers();
  if (users[email] && users[email].passwordHash) return;
  const passwordHash = await hashPassword(password);
  users[email] = {
    name: profile.name || "",
    email,
    passwordHash,
    role: profile.role || "patient",
    nmr: profile.nmr || "",
    createdAt: new Date().toISOString()
  };
  saveUsers(users);
}

async function handleRegister() {
  clearAuthError("registerError");
  const name = document.getElementById("regName").value.trim();
  const email = normalizeEmail(document.getElementById("regEmail").value);
  const password = document.getElementById("regPassword").value;
  const nmr = document.getElementById("regNmr").value.trim();
  const mode = authMode;

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

  if (mode === "doctor" && !isValidNMR(nmr)) {
    showAuthError("registerError", "Doctors must provide a valid NMR/Registration Number (e.g. NMR12345).");
    return;
  }

  if (getUsers()[email]) {
    showAuthError("registerError", "An account with this email already exists. Try signing in.");
    return;
  }

  const profile = {
    name,
    email,
    role: mode,
    nmr: mode === "doctor" ? nmr.toUpperCase() : "",
    createdAt: new Date().toISOString()
  };

  const fb = ensureFirebase();
  if (fb) {
    const existing = await getSharedProfile(email);
    if (existing) {
      showAuthError("registerError", "An account with this email already exists. Try signing in.");
      return;
    }
    try {
      const { createUserWithEmailAndPassword, updateProfile } = window.firebaseModules;
      const cred = await createUserWithEmailAndPassword(fb.auth, email, password);
      await updateProfile(cred.user, { displayName: name }).catch(() => {});
    } catch (err) {
      const code = err && err.code ? err.code : "";
      if (code === "auth/email-already-in-use") {
        showAuthError("registerError", "An account with this email already exists. Try signing in.");
      } else if (code === "auth/weak-password") {
        showAuthError("registerError", "Password is too weak. Use at least 6 characters.");
      } else if (code === "auth/invalid-email") {
        showAuthError("registerError", "Please enter a valid email address.");
      } else {
        showAuthError("registerError", (err && err.message) || "Registration failed. Please try again.");
      }
      return;
    }
    await upsertSharedProfile(profile);
    await ensureLegacyRecord(email, profile, password);
    currentUser = { name, email, role: mode, nmr: profile.nmr };
    localStorage.setItem(SESSION_KEY, JSON.stringify(currentUser));
    showToast("Account created. Welcome!");
    enterApp();
    return;
  }

  const passwordHash = await hashPassword(password);
  const users = getUsers();
  users[email] = { ...profile, passwordHash };
  saveUsers(users);

  currentUser = { name, email, role: mode, nmr: profile.nmr };
  localStorage.setItem(SESSION_KEY, JSON.stringify(currentUser));
  showToast("Account created. Welcome!");
  enterApp();
}

function isValidNMR(nmr) {
  return /^[A-Za-z0-9-]{6,}$/.test(nmr || "");
}

let authMode = "patient";

function setAuthMode(mode) {
  authMode = mode;
  const isDoctor = mode === "doctor";
  document.querySelectorAll(".role-btn").forEach(b => b.classList.remove("active"));
  if (isDoctor) {
    const active = document.getElementById("registerCard").style.display !== "none"
      ? document.getElementById("regDoctorBtn")
      : document.getElementById("loginDoctorBtn");
    if (active) active.classList.add("active");
  } else {
    const active = document.getElementById("registerCard").style.display !== "none"
      ? document.getElementById("regPatientBtn")
      : document.getElementById("loginPatientBtn");
    if (active) active.classList.add("active");
  }
  const loginNmr = document.getElementById("loginNmrField");
  if (loginNmr) loginNmr.style.display = isDoctor ? "block" : "none";
  const regNmrGrp = document.getElementById("regNmr") ? document.getElementById("regNmr").closest(".form-group") : null;
  if (regNmrGrp) regNmrGrp.style.display = isDoctor ? "block" : "none";
}

let pendingReset = null;

function openResetModal(e) {
  if (e) e.preventDefault();
  clearAuthError("resetError");
  document.getElementById("resetStepEmail").style.display = "block";
  document.getElementById("resetStepCode").style.display = "none";
  document.getElementById("resetEmail").value = "";
  document.getElementById("resetCodeInput").value = "";
  document.getElementById("resetNewPass").value = "";
  document.getElementById("resetConfirmPass").value = "";
  document.getElementById("resetModal").style.display = "flex";
}

function closeReset() {
  document.getElementById("resetModal").style.display = "none";
}

function sendResetCode() {
  clearAuthError("resetError");
  const email = normalizeEmail(document.getElementById("resetEmail").value);
  if (!email) {
    showAuthError("resetError", "Enter your registered email address.");
    return;
  }
  const fb = ensureFirebase();
  if (fb && window.firebaseModules.sendPasswordResetEmail) {
    window.firebaseModules.sendPasswordResetEmail(fb.auth, email)
      .then(() => {
        document.getElementById("resetSentEmail").textContent = email;
        document.getElementById("resetStepEmail").style.display = "none";
        document.getElementById("resetStepSent").style.display = "block";
      })
      .catch(err => {
        const code = err && err.code ? err.code : "";
        if (code === "auth/user-not-found" || code === "auth/invalid-email") {
          showAuthError("resetError", "No account found with this email. Check the spelling or register first.");
        } else {
          showAuthError("resetError", (err && err.message) || "Could not send the reset email. Try again.");
        }
      });
    return;
  }
  const users = getUsers();
  if (!users[email]) {
    showAuthError("resetError", "No account found with this email. Check the spelling or register first.");
    return;
  }
  const code = String(Math.floor(100000 + Math.random() * 900000));
  pendingReset = { email, code, expiry: Date.now() + 10 * 60 * 1000 };
  document.getElementById("resetCodeDisplay").textContent = code;
  document.getElementById("resetStepEmail").style.display = "none";
  document.getElementById("resetStepCode").style.display = "block";
}

async function completeReset() {
  clearAuthError("resetError");
  if (!pendingReset || Date.now() > pendingReset.expiry) {
    showAuthError("resetError", "Code expired. Close and request a new one.");
    return;
  }
  const code = document.getElementById("resetCodeInput").value.trim();
  const pass = document.getElementById("resetNewPass").value;
  const confirm = document.getElementById("resetConfirmPass").value;
  if (code !== pendingReset.code) {
    showAuthError("resetError", "Incorrect code. Check the 6-digit code shown above.");
    return;
  }
  if (pass.length < 6) {
    showAuthError("resetError", "New password must be at least 6 characters.");
    return;
  }
  if (pass !== confirm) {
    showAuthError("resetError", "Passwords do not match.");
    return;
  }
  const users = getUsers();
  if (!users[pendingReset.email]) {
    showAuthError("resetError", "This account no longer exists.");
    return;
  }
  users[pendingReset.email].passwordHash = await hashPassword(pass);
  saveUsers(users);
  pendingReset = null;
  closeReset();
  showToast("Password reset. Sign in with your new password.");
}

function enterApp() {
  document.getElementById("auth").style.display = "none";
  document.getElementById("app").style.display = "flex";
  setUserUI(currentUser.name, currentUser.email);
  setDate();
  loadAIConfig();
  loadFirebaseSettings();

  const isDoctor = currentUser.role === "doctor";
  document.querySelectorAll(".nav-item").forEach(n => {
    const roles = (n.dataset.roles || "all").split(",");
    n.style.display = (roles.includes(currentUser.role) || roles.includes("all")) ? "" : "none";
  });

  if (isDoctor) {
    const elDoc = document.getElementById("docNmrLabel");
    if (elDoc) elDoc.textContent = currentUser.nmr || "—";
    showPage("doctor", document.querySelector('.nav-item[data-page="doctor"]'));
  } else {
    showPage("dashboard", document.querySelector('.nav-item[data-page="dashboard"]'));
  }

  const userChipRole = document.querySelector(".user-chip .user-role");
  if (userChipRole) userChipRole.textContent = isDoctor ? "Doctor" : "Member";

  applyAdminUI();

  setTimeout(() => {
    renderDashboardChart();
    renderScoreChart();
    renderDiaryChart();
    if (isDoctor) initFirebase().then(() => { syncDoctorProfile(); loadDoctorDashboard(); });
    else initFirebase();
  }, 100);
}

function showRegister() {
  clearAuthError("loginError");
  document.getElementById("loginCard").style.display = "none";
  document.getElementById("registerCard").style.display = "block";
  setAuthMode(authMode);
}

function showLogin() {
  clearAuthError("registerError");
  document.getElementById("loginCard").style.display = "block";
  document.getElementById("registerCard").style.display = "none";
  setAuthMode(authMode);
}

function applyAdminUI() {
  const item = document.getElementById("registeredNavItem");
  if (item) item.style.display = isAdmin() ? "block" : "none";
}

function logout() {
  localStorage.removeItem(SESSION_KEY);
  if (window.firebaseModules && window._fbAuth && window.firebaseModules.signOut) {
    window.firebaseModules.signOut(window._fbAuth).catch(() => {});
  }
  location.reload();
}

// ── Session Persistence (remember login) ───────
function initAuthState() {
  const raw = localStorage.getItem(SESSION_KEY);
  if (!raw) return;
  try {
    const session = JSON.parse(raw);
    if (session && session.email) {
      currentUser = { name: session.name, email: session.email, role: session.role || "patient", nmr: session.nmr || "" };
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
  settings: ["Settings", "Manage your account and preferences"],
  doctor: ["Patient Log", "Patients who route their reports to you"],
  pdiary: ["Patient Diaries", "View the synced health diaries of your patients"],
  messages: ["Messages", "Chat securely with your doctor or patients"]
};

function showPage(page, el) {
  if ((page === "doctor" || page === "pdiary") && currentUser.role !== "doctor") {
    showToast("Access restricted to doctors only.");
    return;
  }
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

  if (page === "doctor") loadDoctorDashboard();
  else if (page === "pdiary") { setupPDiary(); }
  else if (page === "messages") { setupMessagesPage(); }
  else if (page === "analysis") { loadDoctors(); }
  else if (page === "diary") { loadDiaryFromCloud().then(() => renderDiaryChart(diaryFilter)); }

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
    <div class="entry-note">${escapeHtml(note || "No notes added.")}</div>
    <div class="entry-status good">Logged</div>
  `;

  const container = document.getElementById("diaryEntries");
  container.insertBefore(entry, container.firstChild);

  // Sync to Firestore so the linked doctor can view this diary
  if (db && window.firebaseModules) {
    const { addDoc, collection, serverTimestamp } = window.firebaseModules;
    addDoc(collection(db, "diaryLogs", currentUser.email, "entries"), {
      hydration: hydration ? Number(hydration) : null,
      glucose: glucose ? Number(glucose) : null,
      protein: protein ? Number(protein) : null,
      ph: ph ? Number(ph) : null,
      note: note || "",
      createdAt: serverTimestamp()
    }).catch(e => console.log("Diary sync skipped:", e.message));
  }

  // Clear
  ["logHydration","logGlucose","logProtein","logPH","logNote"].forEach(id => {
    const el = document.getElementById(id);
    if (el) el.value = "";
  });

  closeLogModal();
  showToast("Entry saved successfully");
}

// ── AI Chat (Groq / Llama 3) ───────────────────
const DEFAULT_GROQ_KEY = "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";

function getApiKey() {
  return localStorage.getItem("star_groq_key") || DEFAULT_GROQ_KEY;
}

function getAIModel() {
  const m = localStorage.getItem("star_groq_model");
  if (!m || m === "llama-3.3-70b-versatile" || m === "llama-3.1-8b-instant" || m === "llama-3.2-3b-preview") return "openai/gpt-oss-20b";
  return m;
}

function getSystemPrompt() {
  const d = biomarkerData;
  const clean = arr => arr.filter(v => v != null);
  const ch = clean(d.hydration), cg = clean(d.glucose), cp = clean(d.protein), cph = clean(d.ph);
  const avg = arr => arr.length ? (arr.reduce((a, b) => a + b, 0) / arr.length).toFixed(0) : "—";
  const avgPh = phArr => phArr.length ? (phArr.reduce((a, b) => a + b, 0) / phArr.length).toFixed(1) : "—";
  const latest = {
    hydration: d.hydration[d.hydration.length - 1],
    glucose: d.glucose[d.glucose.length - 1],
    protein: d.protein[d.protein.length - 1],
    ph: d.ph[d.ph.length - 1]
  };
  return `You are Swasthya, a friendly and knowledgeable AI health assistant embedded in the Swasthya Health System dashboard. You help users understand their biomarkers, give health advice, and answer health-related questions.

Current user's biomarker data (this week):
- Hydration: ${ch.length ? ch.join(", ") : "—"}% (avg: ${avg(ch)}%, latest: ${latest.hydration}%)
- Glucose: ${cg.length ? cg.join(", ") : "—"} mg/dL (avg: ${avg(cg)} mg/dL, latest: ${latest.glucose} mg/dL)
- Protein: ${cp.length ? cp.join(", ") : "—"} mg/dL (avg: ${avg(cp)} mg/dL, latest: ${latest.protein} mg/dL)
- pH Level: ${cph.length ? cph.join(", ") : "—"} (avg: ${avgPh(cph)}, latest: ${latest.ph})

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
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
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
      id: 'SWASTHYA-' + Date.now().toString(36).toUpperCase(),
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
let pendingCommentImage = {};

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
  document.getElementById("previewImg").style.filter = "blur(24px)";
  const ov = document.getElementById("previewBlurOverlay");
  if (ov) ov.style.display = "flex";
}

function toggleImageBlur() {
  const img = document.getElementById("previewImg");
  const ov = document.getElementById("previewBlurOverlay");
  if (!img) return;
  const blurred = img.style.filter === "none" || img.style.filter === "";
  if (blurred) {
    img.style.filter = "blur(0px)";
    if (ov) ov.style.display = "none";
  } else {
    img.style.filter = "blur(24px)";
    if (ov) ov.style.display = "flex";
  }
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
    saveReportToFirebase(report);
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
  const text = `SWASTHYA HEALTH ASSESSMENT REPORT
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
  a.download = `SWASTHYA-Report-${r.id}.txt`;
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
  if (section === "registered") renderRegisteredUsers();
}

async function renderRegisteredUsers() {
  const list = document.getElementById("registeredUsersList");
  if (!list) return;
  if (!isAdmin()) {
    list.innerHTML = '<div style="padding:20px;color:var(--text-3);font-size:0.9rem;text-align:center;">Access restricted to the administrator.</div>';
    return;
  }
  let entries = null;
  const fb = ensureFirebase();
  if (fb) {
    try {
      const { getDocs, collection, query, orderBy } = window.firebaseModules;
      const snap = await getDocs(query(collection(db, "users"), orderBy("updatedAt", "desc")));
      const items = [];
      snap.forEach(d => { items.push({ email: d.id, ...d.data() }); });
      if (items.length) entries = items;
    } catch (e) {}
  }
  if (!entries) {
    const users = getUsers();
    entries = Object.keys(users).map(email => ({ email: email || "", ...users[email] }));
  }
  if (!entries.length) {
    list.innerHTML = '<div style="padding:20px;color:var(--text-3);font-size:0.9rem;text-align:center;">No registered accounts yet.</div>';
    return;
  }
  list.innerHTML = entries.map(user => {
    const email = user.email || "";
    const joined = user.createdAt ? new Date(user.createdAt).toLocaleString() : "—";
    return `<div class="registered-user">
      <div class="patient-info">
        <div class="patient-avatar">${(user.name || "?").charAt(0).toUpperCase()}</div>
        <div style="min-width:0;">
          <strong style="font-size:0.92rem;display:block;">${escapeHtml(user.name || "Unknown")}</strong>
          <span style="font-size:0.8rem;color:var(--text-2);word-break:break-all;">${escapeHtml(email)}</span>
          <span style="font-size:0.72rem;color:var(--text-3);display:block;">Role: ${user.role || "patient"} · Joined: ${joined}</span>
        </div>
      </div>
      <button class="btn-ghost small" style="color:var(--red);" onclick="deleteUser('${email.replace(/'/g, "\\'")}')">Delete</button>
    </div>`;
  }).join("");
}

function deleteUser(email) {
  if (!isAdmin()) {
    showToast("Admin only.");
    return;
  }
  if (normalizeEmail(email) === ADMIN_EMAIL) {
    showToast("The admin account cannot be deleted.");
    return;
  }
  if (!confirm(`Delete account "${email}"? This removes their shared profile.`)) return;
  if (db && window.firebaseModules) {
    const { deleteDoc, doc } = window.firebaseModules;
    deleteDoc(doc(db, "users", email)).catch(() => {});
    showToast("Shared profile deleted. Remove the Firebase Auth user in console.firebase.google.com to fully revoke their account.");
  }
  const users = getUsers();
  delete users[email];
  saveUsers(users);
  renderRegisteredUsers();
  showToast("User deleted");
}

function deleteAllUsers() {
  if (!isAdmin()) {
    showToast("Admin only.");
    return;
  }
  if (!confirm("Delete ALL accounts except inventpraveenece2006@gmail.com? This cannot be undone.")) return;
  if (!confirm("Are you absolutely sure? This wipes every other registered account.")) return;
  if (db && window.firebaseModules) {
    const { getDocs, collection, deleteDoc, doc } = window.firebaseModules;
    getDocs(collection(db, "users")).then(snap => {
      const del = [];
      snap.forEach(d => {
        if (normalizeEmail(d.id) !== ADMIN_EMAIL) del.push(deleteDoc(doc(db, "users", d.id)));
      });
      return Promise.all(del);
    }).catch(() => {});
    showToast("Shared profiles cleared. Remove Firebase Auth users in console.firebase.google.com to fully revoke them.");
  }
  const users = getUsers();
  const emails = Object.keys(users);
  let removed = 0;
  emails.forEach(emailItem => {
    if (normalizeEmail(emailItem) !== ADMIN_EMAIL) {
      delete users[emailItem];
      removed++;
    }
  });
  saveUsers(users);
  renderRegisteredUsers();
  showToast(removed ? removed + " account(s) cleared — fresh start" : "No extra accounts to delete");
}

function saveProfile() {
  const name = document.getElementById("settingsName").value;
  const email = document.getElementById("settingsEmail").value;
  if (!name) return;
  currentUser = { ...currentUser, name, email: email || currentUser.email };
  setUserUI(name, currentUser.email);
  const fb = ensureFirebase();
  if (fb) {
    const { updateProfile } = window.firebaseModules;
    if (window._fbAuth.currentUser) updateProfile(window._fbAuth.currentUser, { displayName: name }).catch(() => {});
    upsertSharedProfile({ name, email: currentUser.email, role: currentUser.role, nmr: currentUser.nmr });
  }
  localStorage.setItem(SESSION_KEY, JSON.stringify(currentUser));
  showToast("Profile saved");
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
  const key = localStorage.getItem("star_groq_key") || DEFAULT_GROQ_KEY;
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

function ensureFirebase() {
  if (!window.firebaseModules) return null;
  const config = loadFirebaseConfig();
  if (!config || !config.apiKey || !config.projectId) return null;
  try {
    const { initializeApp, getAuth, getFirestore } = window.firebaseModules;
    if (!window._fbApp) window._fbApp = initializeApp(config);
    if (!window._fbAuth) window._fbAuth = getAuth(window._fbApp);
    if (!db) db = getFirestore(window._fbApp);
    return { auth: window._fbAuth, db };
  } catch (e) {
    return null;
  }
}

async function getSharedProfile(email) {
  if (!db || !window.firebaseModules) return null;
  try {
    const { getDoc, doc } = window.firebaseModules;
    const snap = await getDoc(doc(db, "users", email));
    if (snap.exists()) return snap.data();
  } catch (e) {}
  return null;
}

async function upsertSharedProfile(profile) {
  if (!db || !window.firebaseModules) return;
  try {
    const { setDoc, doc, serverTimestamp } = window.firebaseModules;
    await setDoc(doc(db, "users", profile.email), {
      name: profile.name || "",
      email: profile.email,
      role: profile.role || "patient",
      nmr: profile.nmr || "",
      updatedAt: serverTimestamp()
    }, { merge: true });
  } catch (e) {}
}

async function initFirebase() {
  const config = loadFirebaseConfig();
  if (!config || !window.firebaseModules) {
    const s = document.getElementById("communityStatus");
    if (s) s.innerHTML = "Connect Firebase in <strong>Settings &gt; Community</strong> to enable the community.";
    return;
  }

  try {
    ensureFirebase();
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
      ? `<span class="post-tag ${escapeHtml(p.category)}">${escapeHtml(p.category).replace("-", " ")}</span>`
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
            <button onclick="toggleLike(this)" data-post-id="${p.id}" data-likes="${escapeHtml(JSON.stringify(p.likes || []))}" style="${liked ? "color:var(--red);border-color:var(--red)" : ""}">❤ ${(p.likes || []).length}</button>
          </div>
          <div class="comments-section" id="comments-${p.id}" style="display:none;">
            <div class="comments-list" id="commentsList-${p.id}"></div>
            <div class="comment-input-row">
              <label for="commentImageInput-${p.id}" style="cursor:pointer;font-size:20px;" title="Attach image to comment">🖼️</label>
              <input type="file" id="commentImageInput-${p.id}" accept="image/*" style="display:none" onchange="handleCommentImage('${p.id}', this)">
              <input type="text" id="commentInput-${p.id}" placeholder="Write a comment..." onkeydown="if(event.key==='Enter')postComment('${p.id}')">
              <button class="btn-primary small" onclick="postComment('${p.id}')">Reply</button>
            </div>
            <div id="commentImagePreview-${p.id}" style="display:none;margin-top:6px;position:relative;">
              <img id="commentPreviewImg-${p.id}" style="max-width:120px;max-height:120px;border-radius:8px;object-fit:cover;" alt="Preview">
              <button onclick="removeCommentImage('${p.id}')" style="position:absolute;top:4px;left:4px;background:rgba(0,0,0,0.7);color:white;border:none;border-radius:50%;width:22px;height:22px;cursor:pointer;font-size:12px;">✕</button>
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

async function toggleLike(btn) {
  if (!db || !window.firebaseModules) return;
  const { doc, updateDoc, arrayUnion, arrayRemove } = window.firebaseModules;
  const postId = btn.dataset.postId;
  const ref = doc(db, "posts", postId);
  const name = currentUser.name;
  const currentLikes = JSON.parse(btn.dataset.likes || "[]");

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
            ${c.image ? `<img src="${escapeHtml(c.image)}" style="max-width:150px;max-height:150px;border-radius:8px;object-fit:cover;margin:4px 0;" alt="comment image">` : ""}
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

function handleCommentImage(postId, input) {
  const file = input.files[0];
  if (!file) return;
  const reader = new FileReader();
  reader.onload = e => {
    pendingCommentImage[postId] = e.target.result;
    document.getElementById("commentPreviewImg-" + postId).src = pendingCommentImage[postId];
    document.getElementById("commentImagePreview-" + postId).style.display = "block";
  };
  reader.readAsDataURL(file);
  input.value = "";
}

function removeCommentImage(postId) {
  delete pendingCommentImage[postId];
  document.getElementById("commentImagePreview-" + postId).style.display = "none";
  document.getElementById("commentImageInput-" + postId).value = "";
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
      image: pendingCommentImage[postId] || null,
      createdAt: serverTimestamp()
    });
    await updateDoc(doc(db, "posts", postId), { commentCount: increment(1) });
    input.value = "";
    delete pendingCommentImage[postId];
    const prev = document.getElementById("commentImagePreview-" + postId);
    if (prev) prev.style.display = "none";
    const fileIn = document.getElementById("commentImageInput-" + postId);
    if (fileIn) fileIn.value = "";
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

// ── Doctor Dashboard ────────────────────────────
async function saveReportToFirebase(report) {
  try {
    if (!db || !window.firebaseModules || !report) return;
    const { addDoc, collection, serverTimestamp } = window.firebaseModules;
    await addDoc(collection(db, "reports"), {
      patientName: currentUser.name,
      patientEmail: currentUser.email,
      doctorNmr: (currentDoctorSelection && currentDoctorSelection.nmr) || "",
      typeName: report.typeName,
      label: report.label,
      classification: report.classification,
      risk: report.risk,
      confidence: report.confidence,
      color: report.color,
      texture: report.texture,
      shape: report.shape,
      bristol: report.bristol,
      hydration: report.hydration,
      conditions: report.conditions || [],
      recommendations: report.recommendations || [],
      icon: report.icon,
      reportId: report.id,
      createdAt: serverTimestamp()
    });
  } catch (e) {
    console.log("Report save skipped:", e.message);
  }
}

async function loadDoctorDashboard() {
  const listEl = document.getElementById("patientList");
  if (!listEl) return;
  if (!db || !window.firebaseModules) {
    listEl.innerHTML = 'Connect Firebase in <strong>Settings > Community</strong> to load patient records.';
    return;
  }
  listEl.innerHTML = 'Loading patient records...';
  const { getDocs, collection, query, where, onSnapshot } = window.firebaseModules;

  try {
    const reportsSnap = await getDocs(query(collection(db, "reports"), where("doctorNmr", "==", currentUser.nmr || "")));
    const patients = {};
    let totalReports = 0, highRisk = 0;

    reportsSnap.forEach(doc => {
      const r = { id: doc.id, ...doc.data() };
      totalReports++;
      if (r.risk === "HIGH" || (r.risk || "").toUpperCase() === "HIGH") highRisk++;
      const key = r.patientEmail || "unknown";
      if (!patients[key]) patients[key] = { name: r.patientName || "Unknown", email: key, reports: [] };
      patients[key].reports.push(r);
    });

    const patientArr = Object.values(patients);
    document.getElementById("docStatPatients").textContent = patientArr.length;
    document.getElementById("docStatReports").textContent = totalReports;
    document.getElementById("docStatHighRisk").textContent = highRisk;

    if (patientArr.length === 0) {
      listEl.innerHTML = '<div style="text-align:center;padding:30px;color:var(--text-3);">No patient reports yet. When a patient selects your NMR in their Analysis page, their reports appear here.</div>';
      return;
    }

    listEl.innerHTML = `
      <div style="display:flex;flex-direction:column;gap:12px;">
        ${patientArr.map(p => {
          const latest = p.reports[p.reports.length - 1];
          const riskClass = (latest.risk || "low").toLowerCase();
          return `
            <div class="patient-card">
              <div class="patient-info">
                <div class="patient-avatar">${escapeHtml((p.name || "U").charAt(0).toUpperCase())}</div>
                <div>
                  <strong>${escapeHtml(p.name)}</strong>
                  <div style="font-size:0.78rem;color:var(--text-3);">${escapeHtml(p.email)} · ${p.reports.length} report(s)</div>
                </div>
              </div>
              <div style="display:flex;align-items:center;gap:10px;">
                <span class="risk-chip ${riskClass}">${escapeHtml((latest.risk || "N/A").toUpperCase())}</span>
                <button class="btn-outline small" onclick="togglePatientDetail(this)" data-email="${escapeHtml(p.email)}">View Reports</button>
              </div>
            </div>`;
        }).join("")}
      </div>`;
  } catch (err) {
    listEl.innerHTML = '<div style="text-align:center;padding:20px;color:var(--red);">Failed to load: ' + escapeHtml(err.message) + '</div>';
  }
}

function togglePatientDetail(btn) {
  const email = btn.dataset.email;
  const el = document.getElementById("patientDetail");
  if (!el) return;
  if (el.style.display !== "none" && el.dataset.email === email) {
    el.style.display = "none";
    return;
  }
  el.style.display = "block";
  el.dataset.email = email;
  el.innerHTML = '<div style="padding:20px;color:var(--text-3);">Loading report details...</div>';
  renderPatientDetail(email, el);
}

async function renderPatientDetail(email, container) {
  if (!db || !window.firebaseModules) return;
  const { getDocs, collection, query, orderBy, where } = window.firebaseModules;
  try {
    const snaps = await getDocs(query(collection(db, "reports"), where("doctorNmr", "==", currentUser.nmr || ""), orderBy("createdAt", "desc")));
    const reports = [];
    snaps.forEach(doc => { const r = { id: doc.id, ...doc.data() }; if (r.patientEmail === email) reports.push(r); });

    if (reports.length === 0) {
      container.innerHTML = '<div style="padding:20px;color:var(--text-3);">No reports found for this patient.</div>';
      return;
    }

    container.innerHTML = `
      <div class="dash-panel" style="margin-top:16px;">
        <div class="panel-header">
          <h3>Reports — ${escapeHtml(reports[0].patientName || "Patient")}</h3>
          <button class="btn-ghost small" onclick="document.getElementById('patientDetail').style.display='none'">Close</button>
        </div>
        ${reports.map((r, i) => {
          const rc = (r.risk || "low").toLowerCase();
          return `
            <div class="doctor-report">
              <div class="doctor-report-head">
                <div style="display:flex;align-items:center;gap:8px;">
                  <span style="font-size:20px;">${escapeHtml(r.icon || "🔬")}</span>
                  <div>
                    <strong>${escapeHtml(r.label || "")} — ${escapeHtml(r.classification || "")}</strong>
                    <div style="font-size:0.76rem;color:var(--text-3);">
                      ${escapeHtml(r.typeName || "")} · Confidence ${escapeHtml(r.confidence != null ? r.confidence : "?")}% · <span class="risk-chip ${rc}" style="display:inline-block;">${escapeHtml((r.risk || "").toUpperCase())}</span>
                    </div>
                  </div>
                </div>
                <div style="text-align:right;font-size:0.76rem;color:var(--text-3);" class="doctor-report-meta">
                  <div>${r.createdAt ? formatTimestamp(r.createdAt) : "—"}</div>
                  <div>${escapeHtml(r.reportId || "")}</div>
                </div>
              </div>
              <div class="doctor-report-body">
                <div class="report-confidential">
                  <strong>🔒 CONFIDENTIAL</strong> — Conditions: ${escapeHtml((r.conditions || []).join("; ") || "N/A")}
                </div>
                <div class="report-profile">
                  Bristol: ${escapeHtml(r.bristol || "N/A")} · Color: ${escapeHtml(r.color || "N/A")} · Texture: ${escapeHtml(r.texture || "N/A")} · Hydration: ${escapeHtml(r.hydration != null ? r.hydration + "%" : "N/A")}
                </div>
                <details>
                  <summary style="cursor:pointer;font-size:0.82rem;color:var(--blue);">Show recommendations</summary>
                  <ul style="font-size:0.82rem;padding:8px 0 0 18px;color:var(--text-2);margin:0;">
                    ${(r.recommendations || []).map(rec => `<li>${escapeHtml(rec)}</li>`).join("")}
                  </ul>
                </details>
              </div>
            </div>`;
        }).join("")}
      </div>`;
  } catch (err) {
    container.innerHTML = '<div style="padding:20px;color:var(--red);">Failed: ' + escapeHtml(err.message) + '</div>';
  }
}

function formatTimestamp(ts) {
  try {
    if (ts && ts.toDate) return ts.toDate().toLocaleString("en-GB", { day: "2-digit", month: "short", year: "numeric", hour: "2-digit", minute: "2-digit" });
    if (ts && ts.seconds) return new Date(ts.seconds * 1000).toLocaleString("en-GB");
  } catch (e) {}
  return "—";
}

// ── Doctor sync + patient-doctor linking ────────
function getMyDoctor() {
  try { return JSON.parse(localStorage.getItem("star_my_doctor")) || null; } catch { return null; }
}

function setMyDoctor(info) {
  if (info) localStorage.setItem("star_my_doctor", JSON.stringify(info));
  else localStorage.removeItem("star_my_doctor");
}

function updateDoctorSelection(sel) {
  if (!sel) return;
  const opt = sel.options[sel.selectedIndex];
  const nmr = opt ? opt.value : "";
  const info = nmr ? { nmr, email: opt.dataset.email || "", name: opt.dataset.name || "" } : null;
  currentDoctorSelection = info;
  setMyDoctor(info);
  const st = document.getElementById("doctorPickStatus");
  if (st) st.textContent = nmr ? `Reports will route to ${opt.dataset.name || "the selected doctor"}.` : "No doctor selected — reports stay private on this device.";
}

async function syncDoctorProfile() {
  if (!db || !window.firebaseModules || currentUser.role !== "doctor" || !currentUser.nmr) return;
  const { setDoc, doc, serverTimestamp } = window.firebaseModules;
  try {
    await setDoc(doc(db, "doctors", currentUser.email), {
      name: currentUser.name,
      email: currentUser.email,
      nmr: currentUser.nmr.toUpperCase(),
      updatedAt: serverTimestamp()
    }, { merge: true });
  } catch (e) {
    console.log("Doctor sync skipped:", e.message);
  }
}

async function loadDoctors() {
  if (!db || !window.firebaseModules) return;
  const { getDocs, collection } = window.firebaseModules;
  try {
    const snap = await getDocs(collection(db, "doctors"));
    const docs = [];
    snap.forEach(d => { const r = d.data(); if (r && r.email && r.nmr) docs.push(r); });
    docs.sort((a, b) => (a.name || "").localeCompare(b.name || ""));
    const prev = currentDoctorSelection || getMyDoctor();

    const sel = document.getElementById("reportDoctorSelect");
    if (sel) {
      sel.innerHTML = '<option value="">No doctor selected</option>' + docs.map(d =>
        `<option value="${escapeHtml(d.nmr)}" data-email="${escapeHtml(d.email)}" data-name="${escapeHtml(d.name)}"${prev && prev.nmr === d.nmr ? " selected" : ""}>${escapeHtml(d.name)} (${escapeHtml(d.email)}) · ${escapeHtml(d.nmr)}</option>`
      ).join("");
      updateDoctorSelection(sel);
    }
  } catch (e) {
    console.log("Doctors load skipped:", e.message);
  }
}

// ── Diaries from cloud (patient + doctor view) ──
function diaryEntryHTML(entry, dateObj) {
  const dayNames = ["Sun","Mon","Tue","Wed","Thu","Fri","Sat"];
  const d = dateObj || new Date();
  const dayName = dayNames[d.getDay()];
  const dayNum = d.getDate();
  const h = entry.hydration, g = entry.glucose, p = entry.protein, ph = entry.ph;
  return `
    <div class="diary-entry">
      <div class="entry-day"><span class="day-name">${dayName}</span><span class="day-num">${dayNum}</span></div>
      <div class="entry-metrics">
        ${h != null ? `<div class="entry-metric blue"><span>Hydration</span><strong>${h}%</strong></div>` : ""}
        ${g != null ? `<div class="entry-metric green"><span>Glucose</span><strong>${g} mg/dL</strong></div>` : ""}
        ${p != null ? `<div class="entry-metric orange"><span>Protein</span><strong>${p} mg/dL</strong></div>` : ""}
        ${ph != null ? `<div class="entry-metric purple"><span>pH</span><strong>${ph}</strong></div>` : ""}
      </div>
      <div class="entry-note">${escapeHtml(entry.note || "No notes added.")}</div>
      <div class="entry-status good">Synced</div>
    </div>`;
}

function entryDate(e) {
  try {
    if (e.createdAt && e.createdAt.toDate) return e.createdAt.toDate();
    if (e.createdAt && e.createdAt.seconds) return new Date(e.createdAt.seconds * 1000);
  } catch (err) {}
  return new Date();
}

function rebuildBiomarkerData(entries) {
  biomarkerData.labels = [];
  biomarkerData.hydration = [];
  biomarkerData.glucose = [];
  biomarkerData.protein = [];
  biomarkerData.ph = [];
  entries.forEach(e => {
    const d = entryDate(e);
    biomarkerData.labels.push(d.toLocaleDateString("en-GB", { day: "2-digit", month: "short" }));
    biomarkerData.hydration.push(e.hydration != null ? Number(e.hydration) : null);
    biomarkerData.glucose.push(e.glucose != null ? Number(e.glucose) : null);
    biomarkerData.protein.push(e.protein != null ? Number(e.protein) : null);
    biomarkerData.ph.push(e.ph != null ? Number(e.ph) : null);
  });
}

async function loadDiaryFromCloud() {
  if (!db || !window.firebaseModules || !currentUser.email) return;
  const { getDocs, collection, query, orderBy } = window.firebaseModules;
  try {
    const snap = await getDocs(query(collection(db, "diaryLogs", currentUser.email, "entries"), orderBy("createdAt", "asc")));
    const entries = [];
    snap.forEach(d => entries.push({ id: d.id, ...d.data() }));
    if (entries.length === 0) return;
    rebuildBiomarkerData(entries);
    const container = document.getElementById("diaryEntries");
    if (container) container.innerHTML = entries.map(e => diaryEntryHTML(e, entryDate(e))).join("");
  } catch (e) {
    console.log("Diary load skipped:", e.message);
  }
}

// ── Patient Diaries (doctor) ────────────────────
let pdiaryNames = {};
let pdiaryChartInstance = null;

async function setupPDiary() {
  pdiaryNames = {};
  const listEl = document.getElementById("pdiaryPatientList");
  const viewEl = document.getElementById("pdiaryView");
  if (viewEl) viewEl.style.display = "none";
  if (!listEl) return;
  if (!db || !window.firebaseModules) {
    listEl.innerHTML = 'Connect Firebase in <strong>Settings &gt; Community</strong> to load patient diaries.';
    return;
  }
  listEl.innerHTML = 'Loading your patients...';
  try {
    const patients = await getDoctorPatients();
    if (patients.length === 0) {
      listEl.innerHTML = '<div style="padding:20px;color:var(--text-3);">No patients yet. When a patient selects your NMR, their synced diary becomes viewable here.</div>';
      return;
    }
    patients.forEach(p => { pdiaryNames[p.email] = p.name; });
    listEl.innerHTML = '<div class="pdoc-list">' + patients.map(p => `
      <button class="pdoc-btn" onclick="loadPatientDiary(this)" data-email="${escapeHtml(p.email)}">
        <div class="patient-avatar">${escapeHtml((p.name || "U").charAt(0).toUpperCase())}</div>
        <div>
          <div>${escapeHtml(p.name)}</div>
          <div class="pdoc-meta">${escapeHtml(p.email)}</div>
        </div>
      </button>`).join("") + '</div>';
  } catch (err) {
    listEl.innerHTML = '<div style="padding:20px;color:var(--red);">Failed to load: ' + escapeHtml(err.message) + '</div>';
  }
}

async function getDoctorPatients() {
  const { getDocs, collection, query, where } = window.firebaseModules;
  const snap = await getDocs(query(collection(db, "reports"), where("doctorNmr", "==", currentUser.nmr || "")));
  const map = {};
  snap.forEach(doc => {
    const r = doc.data();
    if (r.patientEmail) map[r.patientEmail] = { email: r.patientEmail, name: r.patientName || "Unknown" };
  });
  return Object.values(map).sort((a, b) => (a.name || "").localeCompare(b.name || ""));
}

async function loadPatientDiary(btn) {
  const email = btn.dataset.email;
  document.querySelectorAll(".pdoc-btn").forEach(b => b.classList.remove("active"));
  if (btn) btn.classList.add("active");
  const viewEl = document.getElementById("pdiaryView");
  if (!viewEl) return;
  viewEl.style.display = "block";
  const nameEl = document.getElementById("pdiaryPatientName");
  if (nameEl) nameEl.textContent = "Health Diary — " + (pdiaryNames[email] || email);
  const entriesEl = document.getElementById("pdiaryEntries");
  if (entriesEl) entriesEl.innerHTML = '<div style="padding:20px;color:var(--text-3);text-align:center;">Loading diary...</div>';
  if (!db || !window.firebaseModules) return;

  const { getDocs, collection, query, orderBy } = window.firebaseModules;
  try {
    const snap = await getDocs(query(collection(db, "diaryLogs", email, "entries"), orderBy("createdAt", "asc")));
    const entries = [];
    snap.forEach(d => entries.push({ id: d.id, ...d.data() }));
    if (entriesEl) {
      entriesEl.innerHTML = entries.length
        ? entries.map(e => diaryEntryHTML(e, entryDate(e))).join("")
        : '<div style="padding:20px;color:var(--text-3);text-align:center;">This patient has no synced diary entries yet.</div>';
    }
    renderPDiaryChart(entries);
  } catch (err) {
    if (entriesEl) entriesEl.innerHTML = '<div style="padding:20px;color:var(--red);text-align:center;">Failed: ' + escapeHtml(err.message) + '</div>';
  }
}

function renderPDiaryChart(entries) {
  const ctx = document.getElementById("pdiaryChart");
  if (!ctx) return;
  if (pdiaryChartInstance) { pdiaryChartInstance.destroy(); pdiaryChartInstance = null; }
  if (!entries.length) return;
  const isDark = document.body.classList.contains("dark");
  const gridColor = isDark ? "rgba(255,255,255,0.06)" : "rgba(0,0,0,0.05)";
  const tickColor = isDark ? "#8a8a8a" : "#94a3b8";
  const labels = entries.map(e => entryDate(e).toLocaleDateString("en-GB", { day: "2-digit", month: "short" }));
  const datasets = [
    { label: "Hydration %", data: entries.map(e => e.hydration != null ? Number(e.hydration) : null), borderColor: "#0891b2" },
    { label: "Glucose mg/dL", data: entries.map(e => e.glucose != null ? Number(e.glucose) : null), borderColor: "#10b981" },
    { label: "Protein mg/dL", data: entries.map(e => e.protein != null ? Number(e.protein) : null), borderColor: "#f59e0b" },
    { label: "pH", data: entries.map(e => e.ph != null ? Number(e.ph) : null), borderColor: "#8b5cf6" }
  ];
  pdiaryChartInstance = new Chart(ctx, {
    type: "line",
    data: { labels, datasets: datasets.map(d => ({ ...d, fill: true, tension: 0.4, pointBackgroundColor: d.borderColor, pointRadius: 4, borderWidth: 2.5 })) },
    options: {
      responsive: true,
      interaction: { mode: "index", intersect: false },
      plugins: {
        legend: { position: "top", labels: { color: tickColor, boxWidth: 12, padding: 14, font: { family: "'DM Sans', sans-serif", size: 12 } } },
        tooltip: { backgroundColor: isDark ? "#1a1a1a" : "white", titleColor: isDark ? "#f5f5f5" : "#1a2332", bodyColor: isDark ? "#a1a1a1" : "#5a6a80", borderColor: isDark ? "#333333" : "#e4eaf2", borderWidth: 1, padding: 12, cornerRadius: 10 }
      },
      scales: {
        x: { grid: { color: gridColor }, ticks: { color: tickColor } },
        y: { grid: { color: gridColor }, ticks: { color: tickColor } }
      }
    }
  });
}

// ── Messages (doctor <-> patient chat) ──────────
let activeChatId = null;
let unsubscribeConv = null;
let unsubscribeMsg = null;
let chatCounterpartyName = "";

function sanitizeDocId(s) {
  return String(s).replace(/[.#$/\[\]]/g, "_");
}

function chatDocId(doctorEmail, patientEmail) {
  return sanitizeDocId(doctorEmail.toLowerCase() + "_" + patientEmail.toLowerCase());
}

async function setupMessagesPage() {
  activeChatId = null;
  chatCounterpartyName = "";
  if (unsubscribeMsg) { unsubscribeMsg(); unsubscribeMsg = null; }
  const hint = document.getElementById("msgPanelHint");
  const title = document.getElementById("msgPanelTitle");
  const sel = document.getElementById("doctorChatSelect");
  const viewEl = document.getElementById("convView");
  const headerEl = document.getElementById("convHeader");
  if (headerEl) headerEl.style.display = "none";
  const inputRow = document.getElementById("msgInputRow");
  if (inputRow) inputRow.style.display = "none";
  const msgList = document.getElementById("msgList");
  if (msgList) msgList.innerHTML = '<div style="padding:40px;text-align:center;color:var(--text-3);font-size:0.9rem;">Select a conversation to start chatting.</div>';

  if (!db || !window.firebaseModules) {
    if (hint) hint.innerHTML = 'Connect Firebase in <strong>Settings &gt; Community</strong> to enable messaging.';
    return;
  }

  if (currentUser.role === "doctor") {
    if (title) title.textContent = "Start a Chat with a Patient";
    if (sel) {
      sel.innerHTML = '<option value="">Select a patient...</option>';
      try {
        const patients = await getDoctorPatients();
        sel.innerHTML = '<option value="">Select a patient...</option>' + patients.map(p =>
          `<option value="${escapeHtml(p.email)}" data-name="${escapeHtml(p.name)}">${escapeHtml(p.name)} (${escapeHtml(p.email)})</option>`
        ).join("");
      } catch (e) {}
    }
    if (hint) hint.textContent = "Patients appear here once they route a report to your NMR. You can chat before or after they send a report.";
  } else {
    if (title) title.textContent = "Talk to Your Doctor";
    if (hint) hint.textContent = "Your reports are shared with the doctor you choose. Pick them here to start a private chat.";
    await loadDoctorsPatientSelect();
  }
  refreshConversationList();
}

async function loadDoctorsPatientSelect() {
  const sel = document.getElementById("doctorChatSelect");
  if (!sel) return;
  if (!db || !window.firebaseModules) return;
  const { getDocs, collection } = window.firebaseModules;
  try {
    const snap = await getDocs(collection(db, "doctors"));
    const docs = [];
    snap.forEach(d => { const r = d.data(); if (r && r.email) docs.push(r); });
    docs.sort((a, b) => (a.name || "").localeCompare(b.name || ""));
    const prev = currentDoctorSelection || getMyDoctor();
    sel.innerHTML = '<option value="">Select a doctor...</option>' + docs.map(d =>
      `<option value="${escapeHtml(d.email)}" data-name="${escapeHtml(d.name)}" data-nmr="${escapeHtml(d.nmr || "")}"${prev && prev.email === d.email ? " selected" : ""}>${escapeHtml(d.name)} (${escapeHtml(d.email)})</option>`
    ).join("");
  } catch (e) {
    console.log("Doctor chat select skipped:", e.message);
  }
}

function refreshConversationList() {
  const listEl = document.getElementById("convList");
  if (!listEl) return;
  if (!db || !window.firebaseModules) {
    listEl.innerHTML = 'Connect Firebase first.';
    return;
  }
  if (unsubscribeConv) { unsubscribeConv(); unsubscribeConv = null; }
  const { collection, onSnapshot, query, where } = window.firebaseModules;
  unsubscribeConv = onSnapshot(query(collection(db, "chats"), where("participants", "array-contains", currentUser.email)), snap => {
    const chats = [];
    snap.forEach(d => { const c = d.data(); if (c.doctorEmail && c.patientEmail) chats.push({ id: d.id, ...c }); });
    chats.sort((a, b) => (a.createdAt ? (a.createdAt.seconds || 0) : 0) - (b.createdAt ? (b.createdAt.seconds || 0) : 0));
    if (!chats.length) {
      listEl.innerHTML = 'No conversations yet.';
      return;
    }
    listEl.innerHTML = chats.map(c => {
      const isDoctor = c.doctorEmail === currentUser.email;
      const name = isDoctor ? (c.patientName || c.patientEmail) : (c.doctorName || c.doctorEmail);
      const initial = (name || "?").charAt(0).toUpperCase();
      return `<div class="conv-row${c.id === activeChatId ? " active" : ""}" onclick="openConversation(this)" data-id="${c.id}" data-name="${escapeHtml(name)}">
        <div class="conv-avatar" style="background:${getAvatarColor(name)}">${escapeHtml(initial)}</div>
        <div>
          <div class="conv-row-name">${escapeHtml(name)}</div>
          <div class="conv-row-sub">${isDoctor ? "Patient" : "Doctor"}</div>
        </div>
      </div>`;
    }).join("");
  }, err => {
    listEl.innerHTML = 'Failed to load conversations.';
  });
}

function startDoctorChat() {
  const sel = document.getElementById("doctorChatSelect");
  if (!sel || !sel.value) { showToast("Select a person first."); return; }
  const opt = sel.options[sel.selectedIndex];
  const email = sel.value;
  const name = opt.dataset.name || email;
  if (currentUser.role === "doctor") {
    openChat(currentUser.email, email, name);
  } else {
    const docNmr = opt.dataset.nmr || "";
    setMyDoctor({ nmr: docNmr, email, name });
    currentDoctorSelection = { nmr: docNmr, email, name };
    openChat(email, currentUser.email, name);
  }
}

async function openChat(doctorEmail, patientEmail, counterpartName) {
  if (!db || !window.firebaseModules) return;
  const { getDoc, doc, setDoc, serverTimestamp } = window.firebaseModules;
  const id = chatDocId(doctorEmail, patientEmail);
  const chatRef = doc(db, "chats", id);
  try {
    const existing = await getDoc(chatRef);
    if (!existing.exists()) {
      await setDoc(chatRef, {
        doctorEmail,
        doctorName: currentUser.role === "doctor" ? currentUser.name : counterpartName,
        patientEmail,
        patientName: currentUser.role === "doctor" ? counterpartName : currentUser.name,
        participants: [doctorEmail, patientEmail],
        createdAt: serverTimestamp()
      });
    }
    openConversation(id, counterpartName);
  } catch (err) {
    showToast("Failed to open chat: " + err.message);
  }
}

function openConversation(elOrId, name) {
  let chatId, pname;
  if (typeof elOrId === "object" && elOrId !== null) {
    chatId = elOrId.dataset.id;
    pname = elOrId.dataset.name || "";
  } else {
    chatId = elOrId;
    pname = name || "";
  }
  activeChatId = chatId;
  chatCounterpartyName = pname;
  document.querySelectorAll(".conv-row").forEach(r => r.classList.remove("active"));
  document.querySelectorAll(".conv-row").forEach(r => { if (r.dataset.id === chatId) r.classList.add("active"); });

  const headerEl = document.getElementById("convHeader");
  if (headerEl) {
    headerEl.style.display = "flex";
    headerEl.innerHTML = `<div class="conv-avatar" style="background:${getAvatarColor(chatCounterpartyName || "U")}">${escapeHtml((chatCounterpartyName || "?").charAt(0).toUpperCase())}</div><div>${escapeHtml(chatCounterpartyName || "Chat")}</div>`;
  }
  const inputRow = document.getElementById("msgInputRow");
  if (inputRow) inputRow.style.display = "flex";
  const msgList = document.getElementById("msgList");
  if (msgList) msgList.innerHTML = '<div style="padding:20px;color:var(--text-3);text-align:center;">Loading messages...</div>';
  if (!db || !window.firebaseModules) return;

  if (unsubscribeMsg) { unsubscribeMsg(); unsubscribeMsg = null; }
  const { collection, onSnapshot, query, orderBy } = window.firebaseModules;
  unsubscribeMsg = onSnapshot(query(collection(db, "chats", chatId, "messages"), orderBy("createdAt", "asc")), snap => {
    if (!msgList) return;
    if (snap.empty) { msgList.innerHTML = '<div style="padding:20px;color:var(--text-3);text-align:center;">Say hello to start the conversation.</div>'; return; }
    msgList.innerHTML = snap.docs.map(d => {
      const m = d.data();
      const mine = m.senderEmail === currentUser.email;
      const ts = (() => { try { return m.createdAt && m.createdAt.toDate ? m.createdAt.toDate().toLocaleTimeString("en-GB", { hour: "2-digit", minute: "2-digit" }) : ""; } catch (e) { return ""; } })();
      return `<div class="pm-msg ${mine ? "mine" : "theirs"}">${escapeHtml(m.text || "")}<div class="pm-meta">${escapeHtml(mine ? "You" : (m.senderName || m.senderEmail || "Doctor"))}${ts ? " · " + ts : ""}</div></div>`;
    }).join("");
    msgList.scrollTop = msgList.scrollHeight;
  }, err => {
    if (msgList) msgList.innerHTML = '<div style="padding:20px;color:var(--red);text-align:center;">Failed to load messages.</div>';
  });
}

function sendChatMessage() {
  const input = document.getElementById("msgInput");
  if (!input) return;
  const text = input.value.trim();
  if (!text) return;
  if (!db || !window.firebaseModules || !activeChatId) { showToast("Open a conversation first."); return; }
  const { addDoc, collection, serverTimestamp } = window.firebaseModules;
  addDoc(collection(db, "chats", activeChatId, "messages"), {
    senderEmail: currentUser.email,
    senderName: currentUser.name,
    text,
    createdAt: serverTimestamp()
  }).catch(err => showToast("Failed to send: " + err.message));
  input.value = "";
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