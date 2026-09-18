# Swasthya Health System — Project Memory

## Identity
- Single-page health dashboard, formerly **"STAR Health System"**, fully rebranded to **SWASTHYA**.
- Live site: https://inventpraveenece2006-commits.github.io/star-health/
- Repo: https://github.com/inventpraveenece2006-commits/star-health (branch `main`)
- Working files: `index.html`, `script.js`, `style.css`, `swasthya-logo.png`
- Safety: always `node --check script.js` before committing. Never commit secrets. Ask before pushing/deploying if unsure.

## Branding notes
- Title "Swasthya Health System"; intro splash spells **SWASTHYA** (9 letters). AI assistant identity = "Swasthya". Reports download as `SWASTHYA-Report-…`.
- Engine name **StarVision** kept intentionally.
- Navbar logo = transparent `swasthya-logo.png` (413×373, 184KB); login page intentionally has NO logo.
- localStorage keys keep the `star_*` prefix for backward compat (`star_users`, `star_session`, `star_groq_key`, `star_groq_model`, `star_my_doctor`, `star_firebase_config`).

## Auth / accounts (localStorage only — NOT a real DB)
- Accounts stored in `localStorage["star_users"]`, keyed by normalized email; passwords hashed (PBKDF2). No server DB of users exists.
- **Each browser/device/domain has its own account list.**
- Registered Users tab (Settings) lists only the accounts in the current browser. Deleting in one place does not affect others.
- Admin email: `ADMIN_EMAIL = "inventpraveenece2006@gmail.com"`; `isAdmin()` gates the Registered Users tab, user deletion, and `deleteAllUsers()`.
- Admin account is undeletable by design. `deleteUser(email)` (per-user) and `deleteAllUsers()` (wipes all except admin) both exist.
- Forgot password is demo-mode: reset code is displayed on-screen (no real email service); `pendingReset` expires in 10 min.

## Health data model
- **Analysis/reports** → Firestore `reports` collection (addDoc), includes `patientName`, `patientEmail`, `doctorNmr` (uppercase NMR or ""), plus report fields. Auto-saved after each `runAIAnalysis`.
- **Health diary** → Firestore `diaryLogs/{patientEmail}/entries/` (addDoc) — synced for doctors to view. Diaries also drive the Chart.js charts via mutable `biomarkerData`.
- **Chats** → Firestore `chats/{docId}` where docId = `sanitize(doctorEmail + "_" + patientEmail)`; subcollection `messages`. Chat doc has `doctorEmail`, `doctorName`, `patientEmail`, `patientName`, `participants: [doctorEmail, patientEmail]` (for `array-contains` queries).
- **Doctors directory** → Firestore `doctors/{email}` {name, email, nmr} upserted whenever a doctor logs in (`syncDoctorProfile`). Patients pick a doctor from this list.
- Firestore project `musicon-cfe95` (apiKey etc. embedded + saved in `star_firebase_config`). Default fallback config hardcoded in `loadFirebaseConfig()`.

## Role-based workspace (current layout)
- **Patients**: Dashboard, Analysis, Health Diary, Messages, AI Assistant, Community, Settings.
- **Doctors**: Patient Log, Patient Diaries, Messages, AI Assistant, Community, Settings. (No Dashboard/Analysis/Diary.)
- Nav is role-filtered via `data-roles="patient|doctor|all"` on `.nav-item`; applied in `enterApp`.
- **Patient Log** (`#doctor` page) shows only patients whose reports have `doctorNmr == currentUser.nmr`; report detail scoped to same NMR.
- **Patient Diaries** (`#pdiary`) lists linked patients; click → reads `diaryLogs/{patientEmail}/entries` + chart (`#pdiaryChart`).
- **Messages** (`#messages`) realtime chat for both roles (`setupMessagesPage`, `refreshConversationList`, `openConversation`, `sendChatMessage`, `startDoctorChat`).

## Gotchas / known behavior
- Reports created BEFORE `doctorNmr` existed are orphaned (don't show in any doctor's Patient Log) — tell doctor to make patients re-run an analysis.
- A doctor only appears in patient pickers after logging in once (that syncs `doctors`).
- On a doctor login, Patient Log may briefly show "Connect Firebase..." then auto-reloads once Firestore is ready.
- Old diary entries: if `createdAt` missing, falls back to `new Date()`.

## Security hardening (implemented)
- CSP meta tag in `<head>` (script/style/font/img/connect-src allowlists incl. `securetoken.googleapis.com`; `object-src 'none'`).
- All user/AI/Firestore content escaped with `escapeHtml` before `innerHTML`; inline onclick handlers use `data-*` attributes, never embedded user strings.
- PBKDF2-SHA256 password hashing (210k iterations, per-user random salt, format `pbkdf2$iter$salt$hash`); legacy SHA-256 accounts auto-upgrade on successful login; `verifyPassword` handles both.
- Role checks are client-side only (static site) — bypassable via localStorage edit; no backend exists by design.

## Outstanding / pending items
- `StegoVault/` (has real secrets: `users.json`, session files) and `steganography/` still TRACKED in the public repo — removal requires user approval.
- Embedded Groq API key `DEFAULT_GROQ_KEY` in script.js is public knowledge → user should rotate/revoke it (approved GitHub secret-scan unblock earlier).
- No login-attempt lockout (user declined).

## Commands
- `git pull --ff-only; if ($?) { git push }` after each commit.
- `node --check script.js` for JS syntax.