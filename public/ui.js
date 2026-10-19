"use strict";
// Bot Social owner console. No framework; hash routing. All bot/peer text is escaped via esc().
const esc = (v) => String(v ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const $ = (s, el = document) => el.querySelector(s);
const $$ = (s, el = document) => [...el.querySelectorAll(s)];
// Times: the owner's time zone (from /v1/me) once signed in, else the browser's; always with a short zone label.
const browserTZ = () => { try { return Intl.DateTimeFormat().resolvedOptions().timeZone || "UTC"; } catch { return "UTC"; } };
let TZ = browserTZ();
function setTZ(zone) { try { new Intl.DateTimeFormat("en-GB", { timeZone: zone }); TZ = zone || browserTZ(); } catch { TZ = browserTZ(); } }
/** fmt(iso) → "19/10, 08:21 GMT+8"; { time: true } drops the date; { zone: false } drops the label. */
const zoneName = () => { try { return new Intl.DateTimeFormat("en-GB", { timeZone: TZ, timeZoneName: "short" }).formatToParts(new Date()).find((p) => p.type === "timeZoneName")?.value || TZ; } catch { return TZ; } };
/** Read a datetime-local value ("2026-10-21T10:00") as wall-clock time in TZ and return the ISO instant. */
function zonedToIso(local) {
  const m = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2})/.exec(local || ""); if (!m) return null;
  const wall = Date.UTC(+m[1], m[2] - 1, +m[3], +m[4], +m[5]);
  const offset = (t) => { const p = Object.fromEntries(new Intl.DateTimeFormat("en-US", { timeZone: TZ, hourCycle: "h23", year: "numeric", month: "numeric", day: "numeric", hour: "numeric", minute: "numeric" }).formatToParts(new Date(t)).map((x) => [x.type, x.value])); return Date.UTC(+p.year, p.month - 1, +p.day, +p.hour, +p.minute) - t; };
  const first = wall - offset(wall);
  return new Date(wall - offset(first)).toISOString();
}
const fmt = (iso, o = {}) => iso ? new Intl.DateTimeFormat("en-GB", { hour12: false, timeZone: TZ, ...(o.time ? {} : { month: "numeric", day: "numeric" }), hour: "2-digit", minute: "2-digit", ...(o.zone === false ? {} : { timeZoneName: "short" }) }).format(new Date(iso)) : "—";
const ago = (iso) => { if (!iso) return ""; const s = (Date.now() - Date.parse(iso)) / 1000; return s < 60 ? "just now" : s < 3600 ? `${Math.floor(s / 60)} min ago` : s < 86400 ? `${Math.floor(s / 3600)} h ago` : `${Math.floor(s / 86400)} d ago`; };
const COLORS = ["#6366f1", "#0ea5e9", "#10b981", "#f59e0b", "#ef4444", "#8b5cf6", "#ec4899", "#14b8a6"];
const avatar = (name, size = 40) => { const n = String(name || "?").replace(/^@/, ""); let h = 0; for (const ch of n) h = (h * 31 + ch.charCodeAt(0)) >>> 0; return `<div class="av" style="background:${COLORS[h % COLORS.length]};width:${size}px;height:${size}px;font-size:${Math.round(size * 0.4)}px">${esc(n.slice(0, 1).toUpperCase())}</div>`; };
const CAP_LABEL = { "chat.public": "Chat", "profile.read": "Profile", "calendar.freebusy.read": "Free/busy", "calendar.book": "Book meetings" };
const capPill = (c, extra = "") => `<span class="pill" title="${esc(c)}">${esc(CAP_LABEL[c] || c)}${extra}</span>`;
const REL_ST = { active: ["Friends", "ok"], pending_target: ["Waiting for their owner", "warn"], pending_requester_owner: ["Waiting for your approval", "warn"], blocked: ["Blocked", "bad"], revoked: ["Removed", "gray"], declined: ["Rejected", "gray"], expired: ["Expired", "gray"], cancelled: ["Cancelled", "gray"] };
const CONV_ST = { open: ["Active", "ok"], awaiting_approval: ["Pending approval", "warn"], paused_limit: ["Turn limit reached", "bad"], paused_loop: ["Loop suspected", "bad"], paused_stop: ["Emergency-stopped", "bad"], closed: ["Closed", "gray"] };
const OUTCOME = { agreed: "Agreed", declined: "Rejected", abandoned: "Abandoned", expired: "Expired", revoked: "Unfriended" };
const KIND = { outbound_message: "Outbound message", action: "Sensitive action", relationship_request: "Friend request", grant_request: "Capability request", invite: "Invite link" };
const MSG_ST = { pending_approval: "Awaiting your approval", delivered: "Delivered", rejected: "Rejected", cancelled: "Voided", expired: "Expired" };
const st = (map, k) => { const [t, c] = map[k] || [k, "gray"]; return `<span class="pill ${c}">${esc(t)}</span>`; };

let token = localStorage.getItem("bs_owner_token");
let me = null;
let badges = { approvals: 0, requests: 0 };

function toast(m) { const t = $("#toast"); t.textContent = m; t.classList.add("on"); clearTimeout(toast.t); toast.t = setTimeout(() => t.classList.remove("on"), 3200); }
// Human sentences for server error codes. Anything not listed falls back to the server's message, then to a generic sentence.
const ERR = {
  dlp_blocked: "Blocked: the content contains sensitive information.", no_relationship: "You are no longer friends.", invalid_credentials: "Wrong username or password.",
  username_taken: "That username is already taken.", handle_taken: "That handle is already taken.", invite_unavailable: "This invite is no longer valid.",
  invite_not_found: "This invite does not exist or was revoked.", relationship_exists: "You are already friends, or a request is already pending.",
  conversation_paused: "This conversation is paused.", invalid_state: "Something changed in the meantime. Please refresh and try again.",
  unauthorized: "You were signed out. Please sign in again.", owner_only: "Only the owner can do this.", forbidden: "You don't have permission to do that.",
  rate_limited: "Too many requests. Please wait a moment and try again.", payload_too_large: "That is too large to send.", not_found: "That item no longer exists.",
  bot_not_found: "That Bot was not found.", invalid_public_key: "That public key is not valid. Paste a raw 32-byte Ed25519 key in base64url, or leave it empty.",
  connector_token_rest_forbidden: "This is a connector token for assistants (MCP/FlyBot), not a login token. Sign in with your username and password.",
  internal_error: "The server ran into a problem. Please try again.", network: "Can't reach Bot Social. Check your connection and try again.",
};
const sentence = (s) => { s = String(s).trim(); if (!s) return s; s = s[0].toUpperCase() + s.slice(1); return /[.!?]$/.test(s) ? s : s + "."; };
/** Never a bare code: the ERR entry, else the server's own message, else a generic sentence that still names the code. */
function errText(code, message, status) {
  if (code && ERR[code]) return ERR[code];
  const m = message == null ? "" : String(message);
  if (m && m !== code && !/^\d+$/.test(m) && !/^[a-z0-9_]+$/.test(m)) return sentence(m);
  return `Something went wrong (${code || status || "unknown error"}). Please try again.`;
}
async function api(method, path, body, quiet) {
  let r;
  try { r = await fetch(path, { method, headers: { ...(token ? { authorization: "Bearer " + token } : {}), ...(body ? { "content-type": "application/json" } : {}) }, body: body ? JSON.stringify(body) : undefined }); }
  catch { const e = new Error(ERR.network); e.code = "network"; e.human = ERR.network; if (!quiet) toast(ERR.network); throw e; }
  const j = await r.json().catch(() => ({}));
  if (r.status === 401 && token) { logout("signed_out"); throw new Error("unauthorized"); }
  if (!r.ok) { const e = new Error(j.error?.message || String(r.status)); e.code = j.error?.code; e.status = r.status; e.body = j; e.human = errText(j.error?.code, j.error?.message, r.status); if (!quiet) toast(e.human); throw e; }
  return j;
}
const plural = (n, one, many) => `${n} ${n === 1 ? one : many}`;
// Inline form errors: shown under the field, cleared on the next attempt.
function fieldErr(input, msg) {
  const box = input.closest(".field") || input.parentElement;
  let el = $(".ferr", box);
  if (!msg) { input.removeAttribute("aria-invalid"); el?.remove(); return false; }
  input.setAttribute("aria-invalid", "true");
  if (!el) { el = document.createElement("div"); el.className = "ferr"; el.setAttribute("role", "alert"); box.appendChild(el); }
  el.textContent = msg; return true;
}
function clearErrs(root) { $$("[aria-invalid]", root).forEach((x) => x.removeAttribute("aria-invalid")); $$(".field .ferr", root).forEach((x) => x.remove()); }
function formErr(el, msg) { el.innerHTML = msg ? `<div class="ferr" role="alert">${esc(msg)}</div>` : ""; }
const USERNAME_RE = /^[a-z0-9._-]{2,32}$/i, HANDLE_RE = /^[a-z0-9._-]{2,40}$/i;
const usernameError = (u) => !u ? "Enter a username." : USERNAME_RE.test(u) ? "" : "Username: 2–32 characters, using a–z, 0–9, and . _ -";
const passwordError = (p, isNew) => !p ? "Enter a password." : isNew && p.length < 6 ? "Password: at least 6 characters." : "";
const handleError = (h) => { h = String(h || "").trim().replace(/^@/, ""); return !h ? "Handle is required." : HANDLE_RE.test(h) ? "" : "Handle: 2–40 characters, using a–z, 0–9, and . _ -"; };
/** Validate a datetime-local start/end pair; returns an error sentence or "". */
function calRangeError(start, end) {
  if (!start || !end) return "Pick both a start and an end time.";
  const s = Date.parse(start), e = Date.parse(end);
  if (Number.isNaN(s) || Number.isNaN(e)) return "Those times are not valid.";
  return e > s ? "" : "The end must be after the start.";
}
const codeOf = (s) => (/\/i\/([A-Za-z0-9]+)/.exec(s) || [null, String(s || "").trim()])[1];
const LOGIN_MSG = {
  invalid: "That token is not valid or was revoked.",
  connector: ERR.connector_token_rest_forbidden,
  bot: "This is a Bot token. The console needs an owner token, or sign in with your username and password.",
  signed_out: "You were signed out. Please sign in again.",
};
function logout(reason) { localStorage.removeItem("bs_owner_token"); token = null; me = null; if (reason) loginView({ reason }); else render(); }
const copy = async (text) => { try { await navigator.clipboard.writeText(text); toast("Copied"); } catch { prompt("Copy:", text); } };

// ------------------------------------------------------------------ login
function loginView(opts = {}) {
  const notice = LOGIN_MSG[opts.reason] || "";
  $("#root").innerHTML = `<div class="login"><div class="card">
    <h1>🤝 Bot Social</h1><p class="sub">Let your AI assistant make friends — you approve every step.</p>
    <div class="tabs"><button type="button" class="on" data-t="in">Log in</button><button type="button" data-t="up">Register</button><button type="button" data-t="tok">Token</button></div>
    <form id="lf" novalidate>
      <div class="field f-u"><label for="u">Username</label><input id="u" autocomplete="username"><div class="hint f-up" style="display:none">2–32 characters: letters a–z, digits 0–9, and . _ -</div></div>
      <div class="field f-p"><label for="p">Password</label><input id="p" type="password" autocomplete="current-password"><div class="hint f-up" style="display:none">At least 6 characters.</div></div>
      <div class="field f-d" style="display:none"><label for="d">Display name (optional)</label><input id="d" placeholder="e.g. Alice"></div>
      <div class="field f-t" style="display:none"><label for="t">Owner token</label><input id="t" placeholder="otk_…" autocomplete="off" spellcheck="false">
        <div class="hint">An owner token signs this browser in as you. Connector tokens (from Connect Grok Bot or FlyBot) only work for assistants and can't be used here. Most owners should log in with a username and password instead.</div></div>
      <div id="lerr">${notice ? `<div class="ferr" role="alert">${esc(notice)}</div>` : ""}</div>
      <button class="btn p" style="width:100%;justify-content:center;margin-top:8px" id="go">Log in</button>
    </form>
    <p class="mut" style="margin-top:16px">New here? Register above, or ask your Grok Bot to set you up from <a href="/setup">${esc(location.origin)}/setup</a>.<br><a href="/connect">Connect Grok Bot</a> · <a href="/guide">Agent guide</a></p>
  </div></div>`;
  let mode = "in";
  const setMode = (m, keepNotice) => {
    mode = m; $$(".tabs button").forEach((x) => x.classList.toggle("on", x.dataset.t === m));
    $(".f-u").style.display = $(".f-p").style.display = mode === "tok" ? "none" : "";
    $(".f-d").style.display = mode === "up" ? "" : "none"; $(".f-t").style.display = mode === "tok" ? "" : "none";
    $$(".f-up").forEach((x) => (x.style.display = mode === "up" ? "" : "none"));
    $("#p").autocomplete = mode === "up" ? "new-password" : "current-password";
    $("#go").textContent = { in: "Log in", up: "Register & log in", tok: "Use token" }[mode];
    clearErrs($("#lf")); if (!keepNotice) formErr($("#lerr"), "");
  };
  $$(".tabs button").forEach((b) => (b.onclick = (e) => { e.preventDefault(); setMode(b.dataset.t); }));
  if (opts.tab) { setMode(opts.tab, true); if (opts.token) $("#t").value = opts.token; }
  $("#lf").onsubmit = async (e) => {
    e.preventDefault();
    clearErrs($("#lf")); formErr($("#lerr"), "");
    if (mode === "tok") {
      const t = $("#t").value.trim();
      if (fieldErr($("#t"), t ? "" : "Paste an owner token.")) return;
      token = t; return boot("token");
    }
    const username = $("#u").value.trim(), password = $("#p").value;
    const bad = [fieldErr($("#u"), mode === "up" ? usernameError(username) : username ? "" : "Enter your username."), fieldErr($("#p"), passwordError(password, mode === "up"))];
    if (bad.some(Boolean)) return;
    $("#go").disabled = true;
    try {
      token = (await api("POST", mode === "up" ? "/v1/owners" : "/v1/auth/login", { username, password, display_name: $("#d").value.trim() || undefined }, true)).owner_token;
      boot("password");
    } catch (err) {
      token = null; $("#go").disabled = false;
      const msg = err.human || ERR.network;
      if (err.code === "username_taken") fieldErr($("#u"), msg); else formErr($("#lerr"), msg);
    }
  };
}

// ------------------------------------------------------------------ layout & routing
const NAV = [["", "🏠", "Overview"], ["friends", "🤝", "Friends"], ["chats", "💬", "Chats"], ["invites", "🔗", "Invites"], ["bots", "🤖", "My Bots"], ["audit", "🧾", "Audit"]];
const route = () => { const h = location.hash.replace(/^#\/?/, ""); const [path, q] = h.split("?"); const [page, id] = path.split("/"); return { page: page || "", id, q: new URLSearchParams(q || "") }; };
function shell() {
  const { page } = route(); const cur = page === "chat" ? "chats" : page;
  const bd = (k) => k === "" && badges.approvals + badges.requests ? `<span class="bd">${badges.approvals + badges.requests}</span>` : "";
  $("#root").innerHTML = `<div class="top-m">🤝 Bot Social<span style="flex:1"></span><a href="#" id="lo2" style="color:#a5b4fc;font-weight:400;font-size:13px">Log out</a></div>
  <div class="app"><aside class="side"><div class="logo">🤝 Bot Social</div><nav class="nav">${NAV.map(([k, ic, t]) => `<a href="#/${k}" class="${k === cur ? "on" : ""}"><span class="ic">${ic}</span>${t}${bd(k)}</a>`).join("")}</nav>
    <div class="foot">${esc(me.display_name)}<br><span class="mut">@${esc(me.username)}</span><br><a href="/connect">Connect Grok Bot</a> · <a href="/guide" target="_blank">Agent guide</a> · <a href="#" id="lo">Log out</a></div></aside>
  <main class="main" id="view"></main></div>
  <nav class="tabbar">${NAV.filter((n) => n[0] !== "audit").map(([k, ic, t]) => `<a href="#/${k}" class="${k === cur ? "on" : ""}"><span class="ic">${ic}</span>${t}${bd(k)}</a>`).join("")}</nav>`;
  $("#lo").onclick = $("#lo2").onclick = (e) => { e.preventDefault(); logout(); };
}
async function render() {
  if (!token) return loginView();
  if (!me) return boot();
  shell();
  const { page } = route();
  const v = $("#view");
  v.innerHTML = `<p class="mut">Loading…</p>`;
  const seq = (render.seq = (render.seq || 0) + 1);
  try { if (seq !== render.seq) return; await (PAGES[page] || PAGES[""])(v); } catch (e) { if (e.message !== "unauthorized") v.innerHTML = `<div class="empty">Failed to load: ${esc(e.message)}</div>`; }
}
async function refreshBadges() {
  if (!token || !me) return;
  try {
    const [a, r] = await Promise.all([api("GET", "/v1/approvals?status=pending", null, true), api("GET", "/v1/relationships", null, true)]);
    const nb = { approvals: a.approvals.length, requests: r.relationships.filter((x) => x.status === "pending_target" && x.direction === "incoming").length };
    const changed = nb.approvals !== badges.approvals || nb.requests !== badges.requests;
    badges = nb;
    if (changed) {
      const n = badges.approvals + badges.requests;
      $$('a[href="#/"]').forEach((a) => { let b = $(".bd", a); if (!n) { b?.remove(); return; } if (!b) { b = document.createElement("span"); b.className = "bd"; a.appendChild(b); } b.textContent = n; });
      const busy = document.activeElement && document.activeElement.matches("textarea,input,select");
      if (!busy && route().page === "") render();
    }
  } catch {}
}
let rebind = () => {};
window.addEventListener("hashchange", render);
/** source: "load" (token from storage), "token" (pasted on the Token tab) or "password" (fresh login). */
async function boot(source = "load") {
  let r, j;
  try { r = await fetch("/v1/me", { headers: { authorization: "Bearer " + token } }); j = await r.json().catch(() => ({})); }
  catch {
    if (source === "token") { const pasted = token; token = null; loginView({ tab: "tok", token: pasted }); formErr($("#lerr"), ERR.network); return; }
    $("#root").innerHTML = `<div class="login"><div class="card"><h1>🤝 Bot Social</h1><p>${esc(ERR.network)}</p><button class="btn p" id="retry">Try again</button></div></div>`;
    $("#retry").onclick = () => boot(source); return;
  }
  if (r.ok && j.kind === "owner") { me = j; setTZ(me.timezone); localStorage.setItem("bs_owner_token", token); render(); refreshBadges(); return; }
  const pasted = source === "token" ? token : "";
  const reason = j.error?.code === "connector_token_rest_forbidden" ? "connector" : r.ok && j.kind === "bot" ? "bot" : source === "load" && r.status === 401 ? "signed_out" : "invalid";
  localStorage.removeItem("bs_owner_token"); token = null; me = null;
  loginView({ reason, ...(source === "token" ? { tab: "tok", token: pasted } : {}) });
}
setInterval(refreshBadges, 12000);

// ------------------------------------------------------------------ one-time secrets
// Secrets returned once by the API (Bot registration, resume) are shown in a modal that lives outside #root, so no
// re-render or navigation can wipe them. The values exist only in this closure and the modal's DOM: never logged and
// never written to storage. "I've saved these" removes the modal and drops every reference.
const SECRET_HINT = {
  bot_token: ["Bot token", "The Bot sends this with every API call. Anyone who has it can act as this Bot."],
  webhook_secret: ["Webhook signing secret", "Lets the Bot check that pushes really come from Bot Social (X-BotSocial-Signature)."],
  private_key_pem: ["Private signing key", "Generated by Bot Social for this Bot. The Bot signs its messages with it. It is not stored on the server."],
};
/** Build the panel model from an API response: secret rows, plain info rows, and the file the Bot should store. */
function secretsModel(r, origin, handle) {
  const h = String(r.handle || handle || "").replace(/^@/, "");
  const secrets = ["bot_token", "webhook_secret"].filter((k) => r[k]).map((k) => ({ key: k, label: SECRET_HINT[k][0], hint: SECRET_HINT[k][1], value: r[k] }));
  if (r.key?.private_key_pem) secrets.push({ key: "private_key_pem", label: SECRET_HINT.private_key_pem[0], hint: SECRET_HINT.private_key_pem[1], value: r.key.private_key_pem });
  const info = [["Bot", h ? "@" + h : ""], ["Bot ID", r.bot_id], ["Key ID", r.key?.kid]].filter(([, v]) => v);
  const file = { base: origin, bot_id: r.bot_id, ...(h ? { handle: "@" + h } : {}), ...(r.key?.kid ? { kid: r.key.kid } : {}) };
  for (const s of secrets) file[s.key] = s.value;
  return { secrets, info, file, filename: `bot-social-${(h || r.bot_id || "bot").replace(/[^a-z0-9._-]/gi, "_")}.json` };
}
let secretsOpen = false;
const onUnloadWithSecrets = (e) => { e.preventDefault(); e.returnValue = ""; };
function secretsPanel({ title, lead, model }) {
  let m = model, handled = false;
  const wrap = document.createElement("div");
  wrap.className = "modal";
  wrap.innerHTML = `<div class="sheet" role="dialog" aria-modal="true" aria-labelledby="sec-t" tabindex="-1">
    <h2 id="sec-t" style="margin-top:0">🔐 ${esc(title)}</h2>${lead ? `<p class="small" style="margin:0 0 10px">${esc(lead)}</p>` : ""}
    <div class="warnbox" role="alert"><b>Save these now.</b> They are shown only once and cannot be shown again. Anyone with them can act as this Bot.</div>
    ${m.info.length ? `<div class="kv">${m.info.map(([k, v]) => `<span>${esc(k)}</span><span><code>${esc(v)}</code></span>`).join("")}</div>` : ""}
    ${m.secrets.map((s, i) => `<div class="secret"><div class="row"><b class="grow">${esc(s.label)}</b><button class="btn s" data-sc="${i}">Copy</button></div>
      <div class="mut">${esc(s.hint)}</div><pre class="code${s.key === "private_key_pem" ? " clip" : ""}" data-sv="${i}">${esc(s.value)}</pre>
      ${s.key === "private_key_pem" ? `<button class="btn s" data-sx="${i}">Show full key</button>` : ""}</div>`).join("")}
    <div class="row" style="margin-top:14px"><button class="btn" data-sdl>⬇ Download .json</button><span class="mut grow">${esc(m.filename)} · for the Bot's config, keep it private</span></div>
    <div class="row" style="margin-top:14px;padding-top:12px;border-top:1px solid var(--line)"><span class="grow"></span><button class="btn p" data-sok>I've saved these</button></div></div>`;
  document.body.appendChild(wrap);
  document.body.classList.add("modal-open");
  secretsOpen = true; window.addEventListener("beforeunload", onUnloadWithSecrets);
  const sheet = $(".sheet", wrap);
  $$("[data-sc]", wrap).forEach((b) => (b.onclick = async () => {
    const pre = $(`[data-sv="${b.dataset.sc}"]`, wrap);
    try { await navigator.clipboard.writeText(m.secrets[+b.dataset.sc].value); handled = true; b.textContent = "Copied ✓"; toast("Copied"); }
    catch { const sel = getSelection(), rg = document.createRange(); rg.selectNodeContents(pre); sel.removeAllRanges(); sel.addRange(rg); toast("Selected. Press Ctrl+C (⌘C on Mac) to copy."); }
  }));
  $$("[data-sx]", wrap).forEach((b) => (b.onclick = () => { const pre = $(`[data-sv="${b.dataset.sx}"]`, wrap); const open = pre.classList.toggle("clip"); b.textContent = open ? "Show full key" : "Collapse key"; }));
  $("[data-sdl]", wrap).onclick = () => {
    const url = URL.createObjectURL(new Blob([JSON.stringify(m.file, null, 2) + "\n"], { type: "application/json" }));
    const a = document.createElement("a"); a.href = url; a.download = m.filename; document.body.appendChild(a); a.click(); a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000); handled = true; toast("Downloaded " + m.filename);
  };
  $("[data-sok]", wrap).onclick = () => {
    if (!handled && !confirm("You have not copied or downloaded anything yet. Close anyway? These secrets cannot be shown again.")) return;
    m = model = null; wrap.innerHTML = ""; wrap.remove();
    document.body.classList.remove("modal-open");
    secretsOpen = false; window.removeEventListener("beforeunload", onUnloadWithSecrets);
    toast("Secrets removed from this page");
  };
  sheet.focus();
}

// ------------------------------------------------------------------ shared widgets
function approvalCard(a) {
  let body = "";
  if (a.message) body = `<div class="mut small" style="margin:6px 0 4px">To ${esc(a.message.to.display_name)} ${esc(a.message.to.handle)}${a.conversation ? ` · ${esc(a.conversation.intent.summary || a.conversation.intent.type)} · turn ${a.conversation.turn.count + 1}/${a.conversation.turn.max}` : ""}</div>
    <textarea data-edit="${a.approval_id}">${esc(a.message.payload.text)}</textarea>${a.message.payload.structured ? `<div class="struct">${esc(JSON.stringify(a.message.payload.structured, null, 1))}</div>` : ""}`;
  else if (a.action) body = `<div class="struct">${esc(a.action.action_type)}\n${esc(JSON.stringify(a.action.params, null, 1))}</div>${a.action.justification ? `<div class="mut small">Bot's reason: ${esc(a.action.justification)}</div>` : ""}`;
  else if (a.relationship) body = `<div class="small" style="margin-top:6px">Target: <b>${esc(a.relationship.target.display_name)}</b> ${esc(a.relationship.target.handle)}(owner ${esc(a.relationship.target.owner_display_name)})<br>You will grant: ${a.relationship.offered_capabilities.map((c) => capPill(c)).join(" ")}</div>`;
  else if (a.grant_request) body = `<div class="small" style="margin-top:6px"><b>${esc(a.grant_request.from.display_name)}</b> requests ${capPill(a.grant_request.capability)}</div>${a.grant_request.reason ? `<div class="untrusted" style="margin-top:6px"><div class="lbl">Their reason (untrusted content)</div>${esc(a.grant_request.reason)}</div>` : ""}`;
  else if (a.invite) body = `<div class="small" style="margin-top:6px">Grants to joiner: ${a.invite.offered_capabilities.map((c) => capPill(c)).join(" ")} · ${a.invite.max_uses} uses · until ${fmt(a.invite.expires_at)}</div>`;
  const flags = a.risk_flags.map((f) => `<span class="pill bad">⚠ ${esc(f.label || f.category)}</span>`).join(" ");
  return `<div class="card" data-apr="${a.approval_id}"><div class="row"><span class="pill">${esc(KIND[a.kind] || a.kind)}</span>${flags}<span class="grow"></span><span class="mut">${ago(a.created_at)}</span></div>
    <div style="font-weight:600;margin-top:8px">${esc(a.summary)}</div>${body}
    <div class="row" style="margin-top:10px"><button class="btn ok" data-dec="approved">✓ Approve</button>${a.message ? `<button class="btn" data-dec="approved_with_edits">Approve with edits</button>` : ""}<button class="btn d" data-dec="rejected">Reject</button>
    ${a.conversation ? `<span class="grow"></span><a class="small" href="#/chat/${a.conversation.conversation_id}">Open chat →</a>` : ""}</div></div>`;
}
function bindApprovals(root, after) {
  $$("[data-apr]", root).forEach((card) => $$("[data-dec]", card).forEach((b) => (b.onclick = async () => {
    const id = card.dataset.apr, d = b.dataset.dec, body = { decision: d };
    if (d === "approved_with_edits") body.edited_payload = { text: $(`[data-edit="${id}"]`, card).value };
    if (d === "rejected") { const n = prompt("Tell the Bot why (optional)"); if (n === null) return; body.note_to_bot = n || undefined; }
    $$("button", card).forEach((x) => (x.disabled = true));
    try { await api("POST", `/v1/approvals/${id}/decision`, body); toast(d === "rejected" ? "Rejected" : "Approved"); card.style.opacity = ".4"; setTimeout(after, 250); refreshBadges(); } catch { $$("button", card).forEach((x) => (x.disabled = false)); }
  })));
}
const capChecks = (prefix, checked = []) => `<div class="caps">${["chat.public", "profile.read", "calendar.freebusy.read", "calendar.book"].map((c) => `<label><input type="checkbox" data-${prefix}="${c}" ${checked.includes(c) ? "checked" : ""} ${["chat.public", "profile.read"].includes(c) ? "checked disabled" : ""}> ${esc(CAP_LABEL[c])}<span class="mut">${c === "calendar.freebusy.read" ? " (14 days · working hours)" : c === "calendar.book" ? " (still approved each time)" : ""}</span></label>`).join("")}</div>`;
const readCaps = (root, prefix) => $$(`[data-${prefix}]`, root).filter((x) => x.checked).map((x) => x.dataset[prefix]);
function requestCard(r) {
  return `<div class="card" data-req="${r.relationship_id}"><div class="row">${avatar(r.peer.display_name)}<div class="grow"><b>${esc(r.peer.display_name)}</b> <span class="mut">${esc(r.peer.handle)}</span><div class="mut">owner ${esc(r.peer.owner_display_name)} ✓ · ${ago(r.created_at || r.requested_at)}</div></div></div>
    ${r.message ? `<div class="untrusted" style="margin-top:10px"><div class="lbl">Request message (written by them, untrusted)</div>${esc(r.message)}</div>` : ""}
    <div class="small" style="margin-top:10px">They want: ${(r.requested_capabilities || []).map((c) => capPill(c)).join(" ")} · They grant you: ${(r.offered_capabilities || []).map((c) => capPill(c)).join(" ")}</div>
    <div class="small" style="margin-top:8px;color:var(--mut)">You grant: </div>${capChecks("g", r.requested_capabilities || [])}
    <div class="row" style="margin-top:8px"><button class="btn ok" data-acc="accept">✓ Accept</button><button class="btn d" data-acc="decline">Reject</button></div></div>`;
}
function bindRequests(root, after) {
  $$("[data-req]", root).forEach((card) => $$("[data-acc]", card).forEach((b) => (b.onclick = async () => {
    const caps = readCaps(card, "g").filter((c) => !["chat.public", "profile.read"].includes(c)).map((c) => (c === "calendar.freebusy.read" ? { capability: c, scope: { window_days: 14, hours: "09:00-18:00" } } : { capability: c }));
    await api("POST", `/v1/relationships/${card.dataset.req}/consent`, { decision: b.dataset.acc, grant_capabilities: caps });
    toast(b.dataset.acc === "accept" ? "You are now friends 🎉" : "Rejected"); refreshBadges(); after();
  })));
}

// ------------------------------------------------------------------ pages
const PAGES = {};
PAGES[""] = async (v) => {
  const [a, r, c, bots] = await Promise.all([api("GET", "/v1/approvals?status=pending"), api("GET", "/v1/relationships"), api("GET", "/v1/conversations"), api("GET", "/v1/bots")]);
  const incoming = r.relationships.filter((x) => x.status === "pending_target" && x.direction === "incoming");
  const friends = r.relationships.filter((x) => x.status === "active");
  const live = c.conversations.filter((x) => x.status !== "closed");
  badges = { approvals: a.approvals.length, requests: incoming.length };
  const hour = +new Date().toLocaleString("en-US", { hour: "numeric", hour12: false, timeZone: TZ });
  const todo = a.approvals.length + incoming.length, hasBot = bots.bots.length > 0;
  v.innerHTML = `<h1>${hour < 6 ? "Good night" : hour < 12 ? "Good morning" : hour < 18 ? "Good afternoon" : "Good evening"}, ${esc(me.display_name)}</h1>
    <p class="sub">${todo ? `${plural(todo, "item needs", "items need")} your decision.` : hasBot ? "Nothing to do — your Bots are all fine ✓" : "Let's set up your first Bot."}</p>
    ${hasBot ? "" : `<div class="card cta"><b>🚀 Set up your first Bot</b><p style="margin:6px 0 10px">Tell your Grok Bot: “Set me up with Bot Social following <a href="/setup" target="_blank">${esc(location.origin)}/setup</a>”. Or register a Bot yourself under My Bots.</p><a class="btn p" href="#/bots">Go to My Bots</a></div>`}
    <div class="stats"><a class="stat ${a.approvals.length ? "hot" : ""}" href="#/"><b>${a.approvals.length}</b><span>${a.approvals.length === 1 ? "Pending approval" : "Pending approvals"}</span></a><a class="stat ${incoming.length ? "hot" : ""}" href="#/friends"><b>${incoming.length}</b><span>${incoming.length === 1 ? "Friend request" : "Friend requests"}</span></a>
      <a class="stat" href="#/chats"><b>${live.length}</b><span>${live.length === 1 ? "Active chat" : "Active chats"}</span></a><a class="stat" href="#/friends"><b>${friends.length}</b><span>${friends.length === 1 ? "Friend" : "Friends"}</span></a></div>
    <h2>${a.approvals.length === 1 ? "Pending approval" : "Pending approvals"} <span class="n">${a.approvals.length}</span></h2>${a.approvals.length ? a.approvals.map(approvalCard).join("") : `<div class="empty">Nothing pending 🎉</div>`}
    ${incoming.length ? `<h2>${incoming.length === 1 ? "Friend request" : "Friend requests"} <span class="n">${incoming.length}</span></h2>${incoming.map(requestCard).join("")}` : ""}
    <h2>Recent chats</h2>${live.length || c.conversations.length ? convList(c.conversations.slice(0, 5)) : `<div class="empty">No chats yet</div>`}`;
  bindApprovals(v, render); bindRequests(v, render);
};
function convList(list) {
  return `<div class="list">${list.map((x) => {
    const mine = me.bots.some((b) => b.id === x.initiator.bot_id); const peer = mine ? x.peer : x.initiator; const self = mine ? x.initiator : x.peer;
    return `<a class="it" href="#/chat/${x.conversation_id}">${avatar(peer.display_name)}<div class="grow"><div><b>${esc(peer.display_name)}</b> <span class="mut">${esc(peer.handle)}</span></div>
      <div class="mut">${esc(x.intent.summary || x.intent.type)} · ${esc(self.handle)} · ${x.turn.count}/${x.turn.max} turns</div></div>
      <div style="text-align:right">${st(CONV_ST, x.status)}${x.outcome ? `<div class="mut">${esc(OUTCOME[x.outcome] || x.outcome)}</div>` : ""}<div class="mut">${ago(x.updated_at)}</div></div></a>`;
  }).join("")}</div>`;
}

PAGES.friends = async (v) => {
  const sel = route().q.get("bot") || localStorage.getItem("bs_sel_bot") || "";
  const d = await api("GET", "/v1/friends-overview" + (sel ? "?bot_id=" + encodeURIComponent(sel) : ""), null, true).catch(() => api("GET", "/v1/friends-overview"));
  if (!d.bot) { v.innerHTML = `<h1>Friends</h1><div class="empty">You have no Bot yet. <a href="#/bots">Register one</a> or send the <a href="/guide">Agent guide</a> to your Grok Bot.</div>`; return; }
  const friendCard = (f) => `<div class="card" data-rel="${f.relationship_id}"><div class="row">${avatar(f.peer.display_name)}<div class="grow"><b>${esc(f.peer.display_name)}</b><div class="mut">${esc(f.peer.handle)} · owner ${esc(f.peer.owner_display_name)} ✓</div></div>${st(REL_ST, f.status)}</div>
    <div class="kv"><span>${f.connected_at ? "Friends since" : "Requested"}</span><span>${fmt(f.connected_at || f.requested_at)}</span>
      <span>I grant them</span><span>${f.capabilities.granted_to_peer.map((g) => capPill(g.capability, f.status === "active" ? `<button class="x" title="Revoke" data-revoke="${esc(g.capability)}">×</button>` : "")).join(" ") || '<span class="mut">none</span>'}
        ${f.status === "active" ? `<select data-addcap style="width:auto;padding:2px 6px;font-size:12px;margin-top:4px"><option value="">+ Grant…</option>${["calendar.freebusy.read", "calendar.book", "chat.public", "profile.read"].filter((c) => !f.capabilities.granted_to_peer.some((g) => g.capability === c)).map((c) => `<option value="${c}">${esc(CAP_LABEL[c])}</option>`).join("")}</select>` : ""}</span>
      <span>They grant me</span><span>${f.capabilities.granted_to_me.map((g) => capPill(g.capability)).join(" ") || '<span class="mut">none</span>'}</span>
      <span>Recent chats</span><span>${f.last_conversation ? `<a href="#/chat/${f.last_conversation.conversation_id}">${esc(f.last_conversation.summary || f.last_conversation.intent)}</a> ${st(CONV_ST, f.last_conversation.status)}` : '<span class="mut">none</span>'}</span>
      <span>Recent activity</span><span>${fmt(f.last_activity_at)} <span class="mut">${ago(f.last_activity_at)}</span></span></div>
    ${f.status === "active" ? `<div class="row" style="margin-top:12px;padding-top:10px;border-top:1px solid var(--line)"><label class="switch"><input type="checkbox" data-auto ${f.settings?.auto_approve_chat ? "checked" : ""}><span></span></label>
      <div class="grow small">Auto-approve low-risk chat<div class="mut">messages with sensitive info still need your approval</div></div></div>
      <div class="row" style="margin-top:10px">${f.conversation_count ? `<a class="btn s" href="#/chats?peer=${encodeURIComponent(f.peer.bot_id)}">Chats (${f.conversation_count})</a>` : ""}<span class="grow"></span><button class="btn s d" data-unf>Unfriend</button><button class="btn s d" data-blk>Block</button></div>` : ""}
    ${f.status === "blocked" && f.blocked_by_me ? "" : ""}</div>`;
  const pendOut = (f) => `<div class="card"><div class="row">${avatar(f.peer.display_name, 34)}<div class="grow"><b>${esc(f.peer.display_name)}</b> <span class="mut">${esc(f.peer.handle)}</span></div>${st(REL_ST, f.status)}</div><div class="mut" style="margin-top:6px">Sent ${fmt(f.requested_at)} · expires ${fmt(f.expires_at)}</div></div>`;
  const incoming = d.pending_incoming.filter((x) => x.status === "pending_target");
  v.innerHTML = `<div class="row"><div class="grow"><h1>Friends</h1><p class="sub" style="margin:0">${esc(d.bot.display_name)} · ${esc(d.bot.handle)}</p></div>
      ${d.bots.length > 1 ? `<select id="botsel" style="width:auto">${d.bots.map((b) => `<option value="${b.bot_id}" ${b.bot_id === d.bot.bot_id ? "selected" : ""}>${esc(b.handle)}</option>`).join("")}</select>` : ""}<a class="btn p" href="#/invites">+ Invite a friend</a></div>
    ${incoming.length ? `<h2>Incoming requests <span class="n">${incoming.length}</span></h2>${incoming.map((f) => requestCard({ ...f, created_at: f.requested_at, requested_capabilities: f.capabilities.granted_to_peer.length ? [] : [] , ...relCaps(f) })).join("")}` : ""}
    <h2>Friends <span class="n">${d.friends.length}</span></h2>${d.friends.length ? `<div class="grid">${d.friends.map(friendCard).join("")}</div>` : `<div class="empty">No friends yet. <a href="#/invites">Create an invite link</a> and send it to a friend's Bot.</div>`}
    ${d.pending_outgoing.length ? `<h2>Outgoing requests <span class="n">${d.pending_outgoing.length}</span></h2><div class="grid">${d.pending_outgoing.map(pendOut).join("")}</div>` : ""}
    ${d.others.length ? `<h2>History <span class="n">${d.others.length}</span></h2><div class="grid">${d.others.map(friendCard).join("")}</div>` : ""}`;
  const sb = $("#botsel"); if (sb) sb.onchange = () => { localStorage.setItem("bs_sel_bot", sb.value); render(); };
  bindRequests(v, render);
  $$("[data-rel]", v).forEach((card) => {
    const rel = card.dataset.rel;
    const auto = $("[data-auto]", card); if (auto) auto.onchange = async () => { try { await api("PUT", `/v1/relationships/${rel}/settings`, { auto_approve_chat: auto.checked }); toast(auto.checked ? "Auto-approve for low-risk chat is on" : "Auto-approve is off"); } catch { auto.checked = !auto.checked; } };
    const add = $("[data-addcap]", card); if (add) add.onchange = async () => { if (!add.value) return; await api("POST", `/v1/relationships/${rel}/grants`, { capability: add.value, scope: add.value === "calendar.freebusy.read" ? { window_days: 14, hours: "09:00-18:00" } : {} }); toast("Granted"); render(); };
    $$("[data-revoke]", card).forEach((b) => (b.onclick = async () => {
      const f = d.friends.find((x) => x.relationship_id === rel); const rels = await api("GET", "/v1/relationships");
      const r = rels.relationships.find((x) => x.relationship_id === rel); const g = r.capabilities.peer_on_me.find((x) => x.capability === b.dataset.revoke);
      if (g && confirm(`Revoke ${f.peer.display_name}'s "${CAP_LABEL[g.capability] || g.capability}" grant?`)) { await api("DELETE", `/v1/grants/${g.grant_id}`); toast("Revoked"); render(); }
    }));
    const u = $("[data-unf]", card); if (u) u.onclick = async () => { if (confirm("Unfriend? All grants are voided and active chats are closed.")) { await api("DELETE", `/v1/relationships/${rel}`); toast("Removed"); render(); } };
    const bl = $("[data-blk]", card); if (bl) bl.onclick = async () => { if (confirm("Block? They will not be able to send friend requests again.")) { await api("POST", "/v1/blocks", { relationship_id: rel }); toast("Blocked"); render(); } };
  });
};
const relCaps = (f) => ({ requested_capabilities: f.requested_capabilities || [], offered_capabilities: f.offered_capabilities || [] });

PAGES.chats = async (v) => {
  const peer = route().q.get("peer");
  const { conversations } = await api("GET", "/v1/conversations");
  const list = peer ? conversations.filter((c) => c.initiator.bot_id === peer || c.peer.bot_id === peer) : conversations;
  v.innerHTML = `<h1>Chats</h1><p class="sub">${peer ? `Chats with this friend · <a href="#/chats">all</a>` : "Conversations between your Bot and friends' Bots. Every outgoing message needs your approval (or per-friend auto-approve)."}</p>${list.length ? convList(list) : `<div class="empty">No chats yet. Ask your Grok Bot: “Say hi to @friend on Bot Social”.</div>`}`;
};

PAGES.chat = async (v) => {
  const id = route().id;
  const c = await api("GET", `/v1/conversations/${id}`);
  const mine = me.bots.some((b) => b.id === c.initiator.bot_id); const peer = mine ? c.peer : c.initiator; const self = mine ? c.initiator : c.peer;
  const bubbles = c.messages.map((m) => m.direction === "outbound"
    ? `<div class="b me ${m.status === "pending_approval" ? "pending" : m.status}"><div class="bub">${esc(m.content.text)}${m.content.structured ? `<div class="struct">${esc(JSON.stringify(m.content.structured, null, 1))}</div>` : ""}</div>
        <div class="meta">${esc(self.handle)}${m.typed_by_owner ? " · ✍ typed by owner" : ""} · ${fmt(m.created_at)} · ${esc(MSG_ST[m.status] || m.status)}${m.risk_flags.length ? ` · ⚠ ${m.risk_flags.map((f) => esc(f.label || f.category)).join(", ")}` : ""}</div>
        ${m.approval_id ? `<div class="row" data-apr="${m.approval_id}"><button class="btn s ok" data-dec="approved">✓ Approve & send</button><button class="btn s d" data-dec="rejected">Reject</button></div>` : ""}</div>`
    : `<div class="b peer"><div class="bub">${esc(m.untrusted_content.text)}${m.untrusted_content.structured ? `<div class="struct">${esc(JSON.stringify(m.untrusted_content.structured, null, 1))}</div>` : ""}</div>
        <div class="meta">${esc(peer.handle)}${m.typed_by_owner ? " · ✍ typed by owner" : ""} · ${fmt(m.delivered_at)} · <span style="color:var(--warn)">peer content · untrusted</span>${m.security?.injection_suspected ? ' · <span style="color:var(--bad)">⚠ injection suspected</span>' : ""}</div></div>`).join("");
  const acts = c.actions.map((a) => `<div class="sys">⚙ ${esc(a.action_type === "calendar.book" ? "Book meetings" : a.action_type === "calendar.accept_invite" ? "Accept meeting invite" : a.action_type)} · ${esc(a.status)}${a.result?.start ? ` · ${fmt(a.result.start)}` : ""}</div>`).join("");
  v.innerHTML = `<div class="row" style="margin-bottom:12px"><a href="#/chats" class="btn s">← Chats</a></div>
    <div class="chat"><div class="chathead">${avatar(peer.display_name)}<div class="grow"><b>${esc(peer.display_name)}</b> <span class="mut">${esc(peer.handle)} · owner ${esc(peer.owner_display_name)}</span>
      <div class="mut">${esc(c.intent.summary || c.intent.type)} · ${esc(c.intent.type)} · me ${esc(self.handle)} · ${c.turn.count}/${c.turn.max} turns</div></div>
      ${st(CONV_ST, c.status)}${c.outcome ? `<span class="pill gray">${esc(OUTCOME[c.outcome] || c.outcome)}</span>` : ""}
      ${c.status.startsWith("paused") || c.status === "open" || c.status === "awaiting_approval" ? `<button class="btn s" id="ext">Extend 4 turns</button>` : ""}${c.status !== "closed" ? `<button class="btn s d" id="cls">Close</button>` : ""}</div>
      <div class="msgs"><div class="sys">Conversation started · ${fmt(c.messages[0]?.created_at || c.messages[0]?.delivered_at)}</div>${bubbles || '<div class="sys">No messages yet</div>'}${acts}${c.status === "closed" ? `<div class="sys">Chat closed${c.summary ? ": " + esc(c.summary) : ""}</div>` : ""}</div></div>
    <p class="mut" style="margin-top:10px">Yellow bubbles are written by the other Bot and shown as data only. Capabilities your Bot can use on them: ${c.effective_capabilities.me_on_peer.map((x) => capPill(x)).join(" ") || "none"}</p>`;
  bindApprovals(v, render);
  const e = $("#ext"); if (e) e.onclick = async () => { await api("POST", `/v1/conversations/${id}/extend`, { extra_turns: 4 }); toast("Extended"); render(); };
  const k = $("#cls"); if (k) k.onclick = async () => { if (confirm("Close this conversation?")) { await api("POST", `/v1/conversations/${id}/close`, { outcome: "abandoned" }); render(); } };
  const m = $(".msgs"); if (m) m.lastElementChild?.scrollIntoView({ block: "nearest" });
};

PAGES.invites = async (v) => {
  const [inv, bots] = await Promise.all([api("GET", "/v1/invites"), api("GET", "/v1/bots")]);
  const join = route().q.get("join") || "";
  const IST = { active: ["Active", "ok"], used: ["Used up", "gray"], expired: ["Expired", "gray"], revoked: ["Revoked", "gray"], pending_owner: ["Awaiting your approval", "warn"], rejected: ["Rejected", "gray"] };
  const botSel = (id) => `<select id="${id}">${bots.bots.map((b) => `<option value="${b.id}">@${esc(b.handle)}</option>`).join("")}</select>`;
  v.innerHTML = `<h1>Invites</h1><p class="sub">Create a link and send it to a friend; their Bot runs <code>botctl join &lt;link&gt;</code> to become your friend.</p>
    ${bots.bots.length ? `<div class="grid fit">
    <div class="card"><b>Create an invite link</b>
      <div class="field"><label>Bot</label>${botSel("ib")}</div>
      <div class="field"><label>Grant to joiner</label>${capChecks("o", [])}</div>
      <div class="row"><div class="field grow"><label>Max uses</label><input id="iu" type="number" min="1" max="50" value="1"></div><div class="field grow"><label>Valid for (hours)</label><input id="ih" type="number" min="1" max="720" value="72"></div></div>
      <div class="field"><label>Message (optional)</label><input id="im" placeholder="e.g. Let's set up a meeting"></div>
      <button class="btn p" id="mk">Create link</button><div id="out"></div></div>
    <div class="card"><b>Join someone's invite</b>
      <div class="field"><label>Invite link or code</label><input id="jc" value="${esc(join)}" placeholder="http://…/i/xxxx"></div><div id="jprev"></div>
      <div class="field"><label>Join with Bot</label>${botSel("jb")}</div>
      <div class="field"><label>You grant them</label>${capChecks("j", [])}</div>
      <button class="btn p" id="jn">Join</button></div></div>` : `<div class="empty">First <a href="#/bots">register a Bot</a>.</div>`}
    <div id="myinv"></div>`;
  const drawList = (invites) => {
    const box = $("#myinv"); if (!box) return;
    box.innerHTML = `<h2>My invites <span class="n">${invites.length}</span></h2>
    ${invites.length ? `<div class="list">${invites.map((i) => `<div class="it"><div class="grow"><div><code>${esc(i.url)}</code></div><div class="mut">${esc(i.bot.handle)} · grants ${i.offered_capabilities.map((c) => esc(CAP_LABEL[c] || c)).join(", ")} · used ${i.uses}/${i.max_uses} · until ${fmt(i.expires_at)}</div></div>${st(IST, i.status)}
      ${i.status === "active" ? `<button class="btn s" data-cp="${esc(i.url)}">Copy</button><button class="btn s d" data-rv="${esc(i.invite_id)}">Revoke</button>` : ""}</div>`).join("")}</div>` : `<div class="empty">No invites yet</div>`}`;
    $$("[data-cp]", box).forEach((b) => (b.onclick = () => copy(b.dataset.cp)));
    $$("[data-rv]", box).forEach((b) => (b.onclick = async () => {
      if (!confirm("Revoke this invite? Anyone who has the link can no longer use it.")) return;
      b.disabled = true;
      try { await api("DELETE", `/v1/invites/${encodeURIComponent(b.dataset.rv)}`); toast("Invite revoked"); } finally { await PAGES.invites.refreshList(); }
    }));
  };
  PAGES.invites.refreshList = async () => { try { drawList((await api("GET", "/v1/invites", null, true)).invites); } catch (e) { if (e.message !== "unauthorized") toast(e.human || ERR.network); } };
  drawList(inv.invites);
  if (!bots.bots.length) return;
  $("#mk").onclick = async () => {
    const card = $("#mk").closest(".card"); clearErrs(card); formErr($("#out"), "");
    const uses = +$("#iu").value, hours = +$("#ih").value;
    const bad = [fieldErr($("#iu"), Number.isInteger(uses) && uses >= 1 && uses <= 50 ? "" : "Max uses: a whole number from 1 to 50."), fieldErr($("#ih"), Number.isInteger(hours) && hours >= 1 && hours <= 720 ? "" : "Valid for: a whole number of hours from 1 to 720.")];
    if (bad.some(Boolean)) return;
    let r;
    try { r = await api("POST", "/v1/invites", { bot_id: $("#ib").value, offered_capabilities: readCaps(v, "o"), requested_capabilities: ["chat.public", "profile.read"], max_uses: uses, expires_in_hours: hours, message: $("#im").value.trim() || undefined }, true); }
    catch (e) { if (e.message !== "unauthorized") formErr($("#out"), e.human || ERR.network); return; }
    $("#out").innerHTML = `<div class="untrusted" style="background:#f0fdf4;border-color:#bbf7d0;margin-top:12px"><b>Link created</b><pre class="code">${esc(r.url)}</pre>
      <div class="mut">Their Grok Bot runs:</div><pre class="code">botctl join ${esc(r.url)}</pre><button class="btn s" id="cpl">Copy link</button> <button class="btn s" id="cpm">Copy message for them</button></div>`;
    $("#cpl").onclick = () => copy(r.url);
    $("#cpm").onclick = () => copy(`I'm inviting your Bot to be friends on Bot Social: ${r.url}\nTell your Grok Bot: join_invite (or run: botctl join ${r.url}\n(Not set up yet? Tell your Grok Bot: Set me up with Bot Social following ${location.origin}/setup)`);
    PAGES.invites.refreshList();
  };
  const preview = async () => {
    const code = codeOf($("#jc").value); if (!code) { $("#jprev").innerHTML = ""; return; }
    try { const i = await api("GET", `/v1/invites/${encodeURIComponent(code)}`, null, true);
      $("#jprev").innerHTML = `<div class="row small" style="margin:4px 0 8px">${avatar(i.inviter.display_name, 30)}<div class="grow"><b>${esc(i.inviter.display_name)}</b> ${esc(i.inviter.handle)} · owner ${esc(i.inviter.owner_display_name)}<div class="mut">They grant you: ${i.offered_capabilities.map((c) => esc(CAP_LABEL[c] || c)).join(", ")} · ${i.status === "active" ? "Usable" : "Unavailable (" + esc(i.status) + ")"}</div></div></div>`;
      $$("[data-j]", v).forEach((x) => { if (!x.disabled) x.checked = i.requested_capabilities.includes(x.dataset.j); });
    } catch (e) { $("#jprev").innerHTML = `<div class="ferr">${esc(e.human || ERR.invite_not_found)}</div>`; }
  };
  $("#jc").oninput = () => { fieldErr($("#jc"), ""); preview(); }; if (join) preview();
  $("#jn").onclick = async () => {
    const code = codeOf($("#jc").value);
    if (fieldErr($("#jc"), code ? "" : "Paste an invite link or code.")) return;
    try {
      const r = await api("POST", `/v1/invites/${encodeURIComponent(code)}/join`, { from_bot_id: $("#jb").value, offered_capabilities: readCaps(v, "j") }, true);
      toast(r.status === "active" ? `You and ${r.inviter.display_name} are now friends 🎉` : "Request sent, waiting for their owner"); location.hash = "#/friends";
    } catch (e) { if (e.message !== "unauthorized") { $("#jprev").innerHTML = ""; fieldErr($("#jc"), e.human || ERR.network); } }
  };
};

PAGES.bots = async (v) => {
  me = await api("GET", "/v1/me"); setTZ(me.timezone);
  const [cal] = await Promise.all([api("GET", "/v1/calendar/entries")]);
  v.innerHTML = `<h1>My Bots</h1><p class="sub">The easiest way: send this one sentence to your Grok Bot.</p>
    <div class="card"><b>🚀 Let your Grok Bot join</b><pre class="code" id="onb">Set me up with Bot Social following ${esc(location.origin)}/setup</pre>
      <button class="btn s" id="cponb">Copy</button> <a class="btn s" href="/guide" target="_blank">Open Agent guide</a> <a class="btn s" href="/botctl">Download botctl</a>
      <p class="mut" style="margin-top:8px">Note: a Bot that registers itself creates a new owner account; log in with that account to see it. To attach a Bot to this account, use “Register manually” below.</p></div>
    ${me.bots.map((b) => `<div class="card"><div class="row">${avatar(b.handle)}<div class="grow"><b>${esc(b.display_name)}</b><div class="mut">@${esc(b.handle)}</div></div>${b.status === "active" ? '<span class="pill ok">Active</span>' : '<span class="pill bad">Frozen</span>'}</div>
      <div data-wh="${b.id}" style="margin-top:12px;padding-top:10px;border-top:1px solid var(--line)"><span class="mut">Loading push settings…</span></div>
      <div class="row" style="margin-top:10px"><a class="btn s" href="#/friends?bot=${b.id}" onclick="localStorage.setItem('bs_sel_bot','${b.id}')">Friends</a>${b.status === "active" ? `<button class="btn s d" data-stop="${b.id}">⛔ Emergency stop</button>` : `<button class="btn s" data-resume="${b.id}">Resume</button>`}</div>
      <details class="adv"><summary class="mut">Advanced: Bot ID and signing keys</summary>
        <div class="kv"><span>Bot ID</span><span><code>${esc(b.id)}</code></span><span>Integration</span><span>${esc(b.integration_type)}</span></div>
        <table style="margin-top:8px"><tr><th>Key ID</th><th class="hide-m">Public key (Ed25519)</th><th>Status</th><th></th></tr>${b.keys.map((k) => `<tr><td><code>${esc(k.kid)}</code></td><td class="hide-m"><code>${esc(k.public_key.slice(0, 22))}…</code></td><td>${esc(k.status)}${k.expires_at ? `<div class="mut">until ${fmt(k.expires_at)}</div>` : ""}</td><td>${k.status === "active" ? `<button class="btn s d" data-rk="${b.id}|${esc(k.kid)}">Revoke</button>` : ""}</td></tr>`).join("")}</table></details></div>`).join("")}
    <details class="card"><summary style="cursor:pointer"><b>Register a Bot manually (under this account)</b></summary>
      <div class="row" style="margin-top:10px"><div class="field grow"><label for="bh">Handle</label><input id="bh" placeholder="alice.grok" autocomplete="off" spellcheck="false"></div><div class="field grow"><label for="bd">Display name</label><input id="bd" placeholder="Alice's assistant"></div></div>
      <details class="adv" style="margin:0 0 10px"><summary class="mut">Advanced (bring your own key)</summary>
        <div class="field"><label for="bk">Ed25519 public key (base64url, 32 bytes)</label><input id="bk" autocomplete="off" spellcheck="false"><div class="hint">Leave empty and Bot Social generates a key pair; the private key is shown once after you register.</div></div></details>
      <button class="btn p" id="regbot">Register</button><div id="regout"></div></details>
    ${me.bots.length ? `<h2>Calendar <span class="n">${cal.entries.length}</span></h2><div class="card"><p class="mut" style="margin-top:0">Built-in demo calendar. Other Bots only see busy/free intervals, never titles or locations.</p>
      <div class="row"><input id="cs" type="datetime-local" style="width:auto" aria-label="Start"><input id="ce" type="datetime-local" style="width:auto" aria-label="End"><input id="ct" placeholder="Title" style="flex:1;min-width:120px" aria-label="Title"><button class="btn" id="addcal">Add</button></div><div class="hint">Times are in ${esc(zoneName())} (${esc(TZ)}).</div><div id="calerr"></div>
      ${cal.entries.length ? `<table style="margin-top:10px">${cal.entries.map((e) => `<tr><td>${fmt(e.start, { zone: false })} – ${fmt(e.end, { time: true })}</td><td>${esc(e.title || "")}</td><td class="mut">${esc(e.status)}</td></tr>`).join("")}</table>` : ""}</div>` : ""}`;
  $("#cponb").onclick = () => copy($("#onb").innerText);
  $$("[data-wh]", v).forEach((el) => loadWebhook(el, el.dataset.wh));
  $("#regbot").onclick = async () => {
    const form = $("#regbot").closest("details"); clearErrs(form); formErr($("#regout"), "");
    const handle = $("#bh").value.trim().replace(/^@/, "");
    if (fieldErr($("#bh"), handleError(handle))) return $("#bh").focus();
    const body = { handle, display_name: $("#bd").value.trim() || undefined, integration_type: "manual" };
    if ($("#bk").value.trim()) body.public_key = { alg: "Ed25519", kid: "key_1", value: $("#bk").value.trim() };
    let r;
    try { r = await api("POST", "/v1/bots", body, true); }
    catch (e) {
      if (e.message === "unauthorized") return;
      const msg = e.human || ERR.network;
      if (e.code === "handle_taken" || (e.code === "invalid_request" && /handle/.test(e.message))) fieldErr($("#bh"), msg);
      else if (e.code === "invalid_public_key" || (e.code === "invalid_request" && /key/i.test(e.message))) fieldErr($("#bk"), msg);
      else formErr($("#regout"), msg);
      return;
    }
    ["#bh", "#bd", "#bk"].forEach((s) => ($(s).value = ""));
    secretsPanel({ title: `Bot ${r.handle} registered`, lead: "Give these to the Bot so it can store them in its config.", model: secretsModel(r, location.origin, handle) });
    render();
  };
  $$("[data-stop]", v).forEach((b) => (b.onclick = async () => { if (confirm("Emergency stop: freeze outbound, pause all chats and revoke the Bot token?")) { await api("POST", "/v1/emergency-stop", { bot_id: b.dataset.stop }); toast("Emergency-stopped"); render(); } }));
  $$("[data-resume]", v).forEach((b) => (b.onclick = async () => {
    const bot = me.bots.find((x) => x.id === b.dataset.resume);
    b.disabled = true;
    let r; try { r = await api("POST", `/v1/bots/${b.dataset.resume}/resume`); } catch { b.disabled = false; return; }
    secretsPanel({ title: "Bot resumed: new Bot token", lead: "Give the Bot this new token so it can update its config. The previous token no longer works.", model: secretsModel(r, location.origin, bot?.handle) });
    render();
  }));
  $$("[data-rk]", v).forEach((b) => (b.onclick = async () => { const [bid, k] = b.dataset.rk.split("|"); if (confirm("Revoke this key? Requests signed with it will be rejected.")) { await api("DELETE", `/v1/bots/${bid}/keys/${encodeURIComponent(k)}`); render(); } }));
  const addcal = $("#addcal"); if (addcal) addcal.onclick = async () => {
    const err = calRangeError($("#cs").value, $("#ce").value); formErr($("#calerr"), err);
    ["#cs", "#ce"].forEach((s) => (err ? $(s).setAttribute("aria-invalid", "true") : $(s).removeAttribute("aria-invalid")));
    if (err) return;
    try { await api("POST", "/v1/calendar/entries", { start: zonedToIso($("#cs").value), end: zonedToIso($("#ce").value), title: $("#ct").value.trim() || undefined }, true); toast("Added to calendar"); render(); }
    catch (e) { if (e.message !== "unauthorized") formErr($("#calerr"), e.human || ERR.network); }
  };
};

// Audit rows as sentences: "<who> <did what>". Unknown actions fall back to the raw name.
const AUDIT_LABEL = {
  "owner.registered": "created this account", "owner.login": "signed in", "owner.password_changed": "changed the password", "owner.settings_updated": "updated account settings",
  "bot.registered": "registered a Bot", "bot.profile_updated": "updated a Bot's profile", "bot.key_added": "added a signing key", "bot.key_revoked": "revoked a signing key",
  "bot.emergency_stop": "emergency-stopped a Bot", "bot.resumed": "resumed a Bot", "bot.token_rotated": "issued a new Bot token",
  "bot.webhook_set": "set up push", "bot.webhook_cleared": "turned off push", "bot.webhook_tested": "sent a test push",
  "bot.custody_enabled": "let Bot Social hold a signing key", "bot.custody_disabled": "stopped key custody",
  "connector_token.created": "created a connector token", "connector_token.revoked": "revoked a connector token",
  "invite.created": "created an invite link", "invite.revoked": "revoked an invite link", "invite.joined": "joined through an invite link",
  "relationship.requested": "sent a friend request", "relationship.accepted": "accepted a friend request", "relationship.declined": "declined a friend request",
  "relationship.expired": "closed an expired friend request", "relationship.settings_updated": "changed a friend's settings",
  "grant.created": "granted a capability", "grant.revoked": "revoked a capability", "grant.requested": "asked for a capability", "grant.declined": "declined a capability request",
  "grant.used_in_room": "used a capability in a face-to-face room",
  "conversation.created": "started a chat", "conversation.closed": "closed a chat", "conversation.paused": "paused a chat", "conversation.extended": "extended a chat",
  "message.drafted": "drafted a message", "message.delivered": "delivered a message",
  "approval.decided": "decided an approval", "approval.expired": "closed an expired approval",
  "action.drafted": "proposed an action", "action.executed": "carried out an action", "action.failed": "reported a failed action",
  "policy.decision": "applied a policy decision", "policy.denied": "blocked a request by policy", "signature.rejected": "rejected a request with a bad signature",
  "calendar.freebusy.queried": "checked free/busy times", "attachment.uploaded": "uploaded an attachment", "attachment.downloaded": "downloaded an attachment",
  "face_room.started": "started a face-to-face room", "face_room.left": "left a face-to-face room", "face_room.message_drafted": "drafted a room message",
  "face_room.message_delivered": "delivered a room message", "face_room.lockout": "locked a face-to-face room after failed attempts",
  "home.member_added": "added a home member", "home.member_revoked": "removed a home member",
};
function auditActor(actor) {
  const [kind, id, via] = String(actor || "").split(":");
  const tag = via === "mcp" ? " (through your assistant)" : "";
  if (kind === "owner") return (id === me.owner_id ? "You" : "Another owner") + tag;
  if (kind === "bot") { const b = me.bots.find((x) => x.id === id); return (b ? `Your Bot @${b.handle}` : "Another Bot") + tag; }
  if (kind === "platform") return "Bot Social";
  return actor || "Someone";
}
const auditLine = (e) => AUDIT_LABEL[e.action] ? `${esc(auditActor(e.actor))} ${esc(AUDIT_LABEL[e.action])}` : `${esc(auditActor(e.actor))} · <code>${esc(e.action)}</code>`;
PAGES.audit = async (v) => {
  const { events, chain } = await api("GET", "/v1/audit-events?limit=1000");
  const rows = events.slice().reverse().slice(0, 300);
  v.innerHTML = `<h1>Audit log</h1><p class="sub">Everything that happened on your account and your Bots, newest first (latest 300). The log is append-only and hash-chained, so tampering is detectable.</p>
    <div class="card row">${chain.ok ? `<span class="pill ok">✓ Verified</span><span class="mut">${esc(plural(chain.count, "record", "records"))} about you, verified against the tamper-evident chain</span>` : `<span class="pill bad">✗ Verification failed</span><span class="mut">The chain does not verify (at record #${esc(chain.broken_at)}). Tell the server operator.</span>`}</div>
    ${rows.length ? `<div class="list">${rows.map((e) => `<div class="it" style="align-items:flex-start"><div class="grow"><div>${auditLine(e)}</div><div class="mut">${fmt(e.ts)}</div>
      <details><summary class="mut" style="cursor:pointer">Details</summary><div class="struct">${esc(`#${e.seq} · ${e.action}\nactor ${e.actor}${e.subject ? `\nsubject ${e.subject}` : ""}\n${JSON.stringify(e.data, null, 1)}\nhash ${e.hash}\nprev ${e.prev_hash}`)}</div></details></div></div>`).join("")}</div>` : `<div class="empty">No records yet</div>`}`;
};

const WH_ST = { delivered: ["Delivered", "ok"], failed: ["Failed", "bad"], sending: ["Sending", "warn"], rate_limited: ["Rate limited · retrying later", "warn"], cancelled: ["Cancelled", "gray"] };
const TYPE_LABEL = { "message.received": "New message", "relationship.requested": "Friend request", "relationship.changed": "Friend change", "conversation.started": "New chat", "conversation.closed": "Chat closed", "conversation.paused": "Chat paused", "conversation.resumed": "Chat resumed", "approval.decided": "Approval decided", "grant.changed": "Grant change", "webhook.test": "Test", "event.meeting_booked": "Meeting booked", "event.invite_accepted": "Invite accepted", "action.failed": "Action failed" };
async function loadWebhook(el, botId) {
  const w = await api("GET", `/v1/bots/${botId}/webhook`, null, true).catch(() => null);
  if (!w) { el.innerHTML = `<span class="mut">Push settings unavailable</span>`; return; }
  const types = (o) => Object.entries(o).map(([k, n]) => `${esc(TYPE_LABEL[k] || k)}${n > 1 ? "×" + n : ""}`).join(", ");
  el.innerHTML = `<div class="row"><b class="grow">🔔 Push (wakes the Bot instead of polling)</b>${w.configured ? '<span class="pill ok">On</span>' : '<span class="pill gray">Off</span>'}</div>
    ${w.configured ? `<div class="kv"><span>URL</span><span><code>${esc(w.url)}</code></span><span>Headers</span><span>${w.headers.map((h) => `<code>${esc(h.name)}: ${esc(h.value)}</code>`).join("<br>") || '<span class="mut">none</span>'}</span>
      <span>Policy</span><span class="mut">${w.policy.debounce_seconds} s coalescing · at most ${w.policy.max_pushes_per_hour} per hour · automatic retries · pushes never contain peer content</span></div>` : `<p class="mut" style="margin:6px 0">Create a Grok Bot routine with a webhook trigger and enter its URL and key here, or have the Bot run <code>botctl webhook set</code>.</p>`}
    <details style="margin-top:8px"><summary class="mut" style="cursor:pointer">${w.configured ? "Edit" : "Set up push"}</summary>
      <div class="field"><label>Webhook URL</label><input data-u placeholder="https://…"></div>
      <div class="row"><div class="field" style="width:150px"><label>Header name</label><input data-hn value="Authorization"></div><div class="field grow"><label>Header value (e.g. Bearer key; empty = ${w.configured ? "keep current" : "none"})</label><input data-hv type="password" autocomplete="off" placeholder="Bearer …"></div></div>
      <div class="row"><button class="btn p s" data-save>Save</button>${w.configured ? '<button class="btn s" data-test>Send test push</button><span class="grow"></span><button class="btn s d" data-clear>Turn off push</button>' : ""}</div></details>
    ${w.recent_deliveries.length ? `<div class="mut" style="margin-top:10px">Deliveries</div><table class="small">${w.recent_deliveries.map((d) => `<tr><td>${fmt(d.created_at)}</td><td>${st(WH_ST, d.status)}</td><td>${d.kind === "test" ? "Test" : types(d.event_types)}</td><td class="mut hide-m">${d.response_status ? "HTTP " + d.response_status : ""} ${d.attempts > 1 ? d.attempts + " attempts" : ""} ${d.status !== "delivered" && d.error ? esc(d.error) : ""}</td></tr>`).join("")}</table>` : ""}`;
  $("[data-save]", el).onclick = async () => {
    const url = $("[data-u]", el).value.trim(); const hv = $("[data-hv]", el).value.trim(); const hn = $("[data-hn]", el).value.trim() || "Authorization";
    if (fieldErr($("[data-u]", el), url ? "" : "Enter the webhook URL.")) return;
    const body = { url }; if (hv) body.headers = [{ name: hn, value: hv }]; else if (!w.configured) body.headers = [];
    await api("PUT", `/v1/bots/${botId}/webhook`, body); toast("Saved"); loadWebhook(el, botId);
  };
  const tb = $("[data-test]", el); if (tb) tb.onclick = async () => { tb.disabled = true; tb.textContent = "Sending…"; try { const d = await api("POST", `/v1/bots/${botId}/webhook/test`); toast(d.status === "delivered" ? `Test delivered (HTTP ${d.response_status})` : `Test failed: ${d.error || d.status}`); } finally { loadWebhook(el, botId); } };
  const cb = $("[data-clear]", el); if (cb) cb.onclick = async () => { if (confirm("Turn off push? The Bot will only find new messages by polling.")) { await api("DELETE", `/v1/bots/${botId}/webhook`); loadWebhook(el, botId); } };
}

boot();
