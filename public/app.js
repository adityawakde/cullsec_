let token = localStorage.getItem("cullsec-token") || "";
let currentScanId = null; let currentFindings = []; let scansList = [];
const $ = (id) => document.getElementById(id);
function setTheme(t){ document.documentElement.setAttribute("data-theme", t); localStorage.setItem("cullsec-theme", t); }
(function(){ const saved = localStorage.getItem("cullsec-theme"); setTheme(saved || (matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light")); })();
$("themeLight").onclick = () => setTheme("light"); $("themeDark").onclick = () => setTheme("dark");
function headers(){ return { "Content-Type": "application/json", Authorization: `Bearer ${token}` }; }
async function api(path, opts = {}){ const r = await fetch(path, { ...opts, headers: headers() }); const j = await r.json().catch(() => ({})); if (!r.ok) throw new Error(j.error || "Request failed"); return j; }
function setSignedInUser(acct){ if (!acct) return; localStorage.setItem("cullsec-account", JSON.stringify(acct)); $("siName").textContent = acct.name || ""; $("siEmail").textContent = acct.email || ""; if ($("profileName")) $("profileName").value = acct.name || ""; }
function showSignedIn(show){
  $("signedOut").hidden = show; $("signedIn").hidden = !show; $("signOut").hidden = !show; $("editProfile").hidden = !show; $("signedInUser").hidden = !show; if ($("globalFooter")) $("globalFooter").hidden = !show; if ($("themePill")) $("themePill").hidden = show; window.scrollTo(0, 0);
  if (show) { try { const a = JSON.parse(localStorage.getItem("cullsec-account") || "null"); if (a) setSignedInUser(a); } catch (e) {} loadDashboard(); }
}
$("signOut").onclick = () => { token = ""; localStorage.removeItem("cullsec-token"); localStorage.removeItem("cullsec-account"); showSignedIn(false); };
$("editProfile").onclick = () => { $("profileForm").hidden = !$("profileForm").hidden; };
$("cancelProfile").onclick = () => { $("profileForm").hidden = true; };
$("saveProfile").onclick = async () => { try { const r = await api("/api/profile", { method: "POST", body: JSON.stringify({ name: $("profileName").value }) }); setSignedInUser(r.account); $("profileStatus").textContent = "Name saved."; $("profileForm").hidden = true; } catch (e) { $("profileStatus").textContent = e.message; } };
$("password").addEventListener("input", (e) => {
  const v = e.target.value;
  $("pwLen").style.color = v.length >= 8 ? "green" : ""; $("pwLower").style.color = /[a-z]/.test(v) ? "green" : "";
  $("pwUpper").style.color = /[A-Z]/.test(v) ? "green" : ""; $("pwNum").style.color = /[0-9]/.test(v) ? "green" : "";
  $("pwSym").style.color = /[^A-Za-z0-9]/.test(v) ? "green" : "";
});
try { const savedLogin = JSON.parse(localStorage.getItem("cullsec-login") || "null"); if (savedLogin) { if ($("email")) $("email").value = savedLogin.email || ""; if ($("password")) $("password").value = savedLogin.password || ""; if ($("name") && savedLogin.name) $("name").value = savedLogin.name; if ($("rememberLogin")) $("rememberLogin").checked = true; } } catch (e) {}
$("signinForm").addEventListener("submit", async (e) => {
  e.preventDefault(); $("signinError").textContent = "";
  try {
    const r = await fetch("/api/signin", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ name: $("name").value, email: $("email").value, password: $("password").value }) });
    const j = await r.json(); if (!r.ok) throw new Error(j.error || "Sign-in failed");
    token = j.token; localStorage.setItem("cullsec-token", token); if ($("rememberLogin") && $("rememberLogin").checked) { localStorage.setItem("cullsec-login", JSON.stringify({ email: $("email").value, password: $("password").value, name: $("name").value })); } else { localStorage.removeItem("cullsec-login"); } setSignedInUser(j.account); showSignedIn(true);
  } catch (err) { $("signinError").textContent = err.message; }
});
document.querySelectorAll(".tabbtn").forEach((b) => b.onclick = () => {
  document.querySelectorAll(".tabbtn").forEach((x) => x.classList.remove("active")); b.classList.add("active");
  document.querySelectorAll(".tab").forEach((x) => x.classList.remove("active")); $("tab-" + b.dataset.tab).classList.add("active");
});
const esc = (v) => String(v ?? "").replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
const sevClass = (s) => `chip-${String(s).replace(" ", "-")}`;
async function loadDashboard(){
  try {
    const d = await api("/api/dashboard"); scansList = d.scans;
    $("overviewEmpty").hidden = d.scans.length > 0; $("overviewDashboard").hidden = d.scans.length === 0;
    $("savedScansList").innerHTML = d.scans.map((s) => `<div class="row"><div><strong>${esc(s.name)}</strong><div class="meta">${s.total} findings</div></div><span><button type="button" data-open="${s.id}">Open</button> <button type="button" data-del="${s.id}">Delete</button></span></div>`).join("");
    $("savedScansEmpty").hidden = d.scans.length > 0;
    $("savedScansList").querySelectorAll("[data-open]").forEach((b) => b.onclick = async () => { const sc = await api(`/api/scans/${b.dataset.open}`); currentScanId = sc.scan.id; currentFindings = sc.findings; $("searchBox").value = ""; $("sevFilter").value = ""; $("statusFilter").value = ""; $("triageStatus").textContent = `Opened: ${sc.scan.name} — ${sc.findings.length} findings.`; $("aiPanel").textContent = "Select a finding to see its breakdown."; renderFindings(currentFindings); document.querySelector('[data-tab="triage"]').click(); const fp = $("findingsPanel"); if (fp) fp.scrollIntoView({ block: "start" }); });
    $("savedScansList").querySelectorAll("[data-del]").forEach((b) => b.onclick = async () => { if (!confirm(`Delete this scan and its findings?`)) return; await api(`/api/scans/${b.dataset.del}`, { method: "DELETE" }); if (String(currentScanId) === b.dataset.del) { currentScanId = null; currentFindings = []; } loadDashboard(); });
    $("compareEmpty").hidden = d.scans.length >= 2; $("boardEmpty").hidden = d.scans.length > 0;
    const sev = d.severity || {};
    const threatEl = $("threatLevel"); if (threatEl) { const lvl = (sev.Critical || 0) > 0 ? ["HIGH", "threat-high"] : (sev.High || 0) > 0 ? ["ELEVATED", "threat-elevated"] : (d.total || 0) > 0 ? ["LOW", "threat-low"] : ["—", "threat-none"]; threatEl.textContent = `🛡 Threat level: ${lvl[0]}`; threatEl.className = `threat-chip ${lvl[1]}`; }
    const total = d.total || 0;
    const fixed = (d.status && d.status.Fixed) || 0;
    const progress = total ? Math.round((fixed / total) * 100) : 0;
    const statCard = (label, num, sub, cls) => `<div class="stat ${cls || ""}"><div class="stat-label">${label}</div><div class="stat-num">${num}</div><div class="stat-sub">${sub}</div></div>`;
    $("stats").innerHTML = `<div class="stat-grid">${statCard("Total findings", total, `${d.scans.length} saved scans`, "")}${statCard("Critical", sev.Critical || 0, "Fix first", "critical")}${statCard("High", sev.High || 0, "Fix next", "high")}${statCard("Medium", sev.Medium || 0, "Plan a fix", "medium")}${statCard("Low", sev.Low || 0, "Lower priority", "low")}${statCard("Info", sev.Info || 0, "For reference", "info")}</div><div class="panel"><h3>Remediation progress</h3><p>${fixed} of ${total} fixed · ${progress}%</p><div class="progress-track"><div class="progress-fill" style="width:${progress}%"></div></div><p>${Object.entries(d.status || {}).map(([k, v]) => `<span class="chip chip-status">${esc(k)}: ${v}</span>`).join(" ") || "No findings yet."}</p></div>`;
    $("scanSummary").innerHTML = `<div class="panel"><h3>Per-scan summary</h3><div class="row-list">${d.perScan.map((s) => `<div class="row"><div><strong>${esc(s.name)}</strong><div class="meta">${s.total} findings</div></div><div class="meta">${s.critical} critical · ${s.fixed} fixed</div></div>`).join("") || "<p>No scans yet.</p>"}</div></div>`;
    $("riskyHosts").innerHTML = `<div class="row-list">${d.riskiestHosts.map((h) => `<div class="row"><strong>${esc(h.host)}</strong><span class="meta">${h.count} findings · max ${h.max}</span></div>`).join("") || "<p>No hosts yet.</p>"}</div>`;
    const maxSvc = Math.max(1, ...(d.commonServices || []).map((s) => s.count));
    $("commonServices").innerHTML = `<div class="svc-list"><div class="svc-head"><span></span><span>Service</span><span>Exposure</span><span>Findings</span></div>${d.commonServices.map((s, i) => `<div class="svc-row"><span class="svc-rank">${i + 1}</span><span class="svc-name">${esc(s.service)}</span><span class="svc-bar"><i style="width:${Math.round((s.count / maxSvc) * 100)}%"></i></span><span class="svc-count">${s.count} finding${s.count === 1 ? "" : "s"}</span></div>`).join("") || "<p>No services yet.</p>"}</div>`;
    $("trend").innerHTML = `<div class="row-list">${d.trend.map((t) => `<div class="row"><strong>${esc(t.name)}</strong><span class="meta">${t.total} findings · ${t.critical} critical · avg ${t.avg}</span></div>`).join("") || "<p>No scans yet.</p>"}</div>`;
    $("hostInventory").innerHTML = `<div class="svc-list">${d.hostInventory.map((h) => `<div class="svc-row host-row"><span class="svc-name host-name">${esc(h.host)}</span><span class="host-svcs">${[...new Set(String(h.services || "").split(", ").filter(Boolean))].map((s) => `<span class="svc-pill">${esc(s)}</span>`).join("") || "<span class=\"meta\">—</span>"}</span><span class="svc-count">max ${h.maxScore}</span></div>`).join("") || "<p>No hosts yet.</p>"}</div>`;
    const opts = d.scans.map((s) => `<option value="${s.id}">${s.name}</option>`).join("");
    $("compareA").innerHTML = opts; $("compareB").innerHTML = opts;
    renderBoard(); renderPlatform();
  } catch (e) { /* token may be invalid */ }
}
async function renderBoard(){
  const d = await api("/api/dashboard");
  // Board shows latest scan findings
  if (!d.scans.length) { $("board").innerHTML = ""; return; }
  const scan = await api(`/api/scans/${d.scans[0].id}`);
  const statuses = ["Open", "In progress", "Fixed", "Risk accepted", "False positive"];
  const card = (f) => `<div class="finding sev-${f.severity}"><div class="finding-head"><span class="chip ${sevClass(f.severity)}">${esc(f.severity)}</span><span class="score-badge">${f.score}</span></div><div class="finding-title">${esc(f.host)}:${f.port} ${esc(f.service)}</div><div class="finding-meta">${esc(f.title || "")}</div><select data-id="${f.id}"><option>Open</option><option>In progress</option><option>Fixed</option><option>Risk accepted</option><option>False positive</option></select></div>`;
  $("board").innerHTML = `<p class="lede">Latest scan: ${esc(scan.scan ? scan.scan.name : "")} · ${scan.findings.length} findings</p><div class="board-columns">${statuses.map((st) => `<div class="board-col"><h3>${st} (${scan.findings.filter((f) => f.status === st).length})</h3>${scan.findings.filter((f) => f.status === st).map(card).join("") || "<p>No findings.</p>"}</div>`).join("")}</div>`;
  $("board").querySelectorAll("select").forEach((sel) => { const f = scan.findings.find((x) => String(x.id) === sel.dataset.id); if (f) sel.value = f.status; sel.onchange = async () => { await api(`/api/findings/${f.id}`, { method: "PATCH", body: JSON.stringify({ status: sel.value }) }); loadDashboard(); }; });
}
function renderFindings(list){
  const q = ($("searchBox").value || "").toLowerCase(); const sev = $("sevFilter").value; const st = $("statusFilter").value;
  let out = list.filter((f) => (!q || `${f.host} ${f.service} ${f.title}`.toLowerCase().includes(q)) && (!sev || f.severity === sev) && (!st || f.status === st));
  const sort = $("sortSelect").value;
  if (sort === "score-desc") out.sort((a, b) => b.score - a.score); if (sort === "score-asc") out.sort((a, b) => a.score - b.score); if (sort === "host") out.sort((a, b) => a.host.localeCompare(b.host));
  $("findingsList").innerHTML = out.map((f) => `<div class="finding sev-${f.severity}"><div class="finding-head"><span><span class="chip ${sevClass(f.severity)}">${esc(f.severity)}</span> <span class="chip chip-status">${esc(f.status)}</span></span><span class="score-badge">${f.score}</span></div><div class="finding-title">${esc(f.host)}:${f.port} ${esc(f.service)}</div><div class="finding-meta">${esc(f.title || "")}${f.version ? ` · ${esc(f.version)}` : ""}${f.scanner ? ` · ${esc(f.scanner)}` : ""}</div><button type="button" onclick="showWhy(${f.id})">Why this score?</button><div class="why-answer" id="why-${f.id}"></div></div>`).join("") || "<p>No findings match.</p>";
}
window.showWhy = (id) => { const f = currentFindings.find((x) => x.id === id); if (!f) return; const b = f.breakdown; const part = (label, v) => `<div><b>${v}</b><span>${label}</span></div>`; const html = `<p><strong>Deterministic breakdown for ${esc(f.host)}:${f.port}.</strong></p><div class="breakdown-grid">${part("Base", b.base)}${part("Risky service", b.riskyService)}${part("Version", b.version)}${part("Scanner severity", b.scannerSeverity)}${part("Exposure", b.exposure)}${part("Asset criticality", b.assetCriticality)}${part("Host context", b.hostContext)}${part("Total", b.total)}</div><p>${esc((b.reasons || []).join("; "))}</p>`; $("aiPanel").innerHTML = html; const inline = document.getElementById(`why-${id}`); if (inline) { inline.innerHTML = html; inline.scrollIntoView({ block: "nearest" }); } };
["searchBox","sevFilter","statusFilter","sortSelect"].forEach((id) => $(id).addEventListener("input", () => renderFindings(currentFindings)));
async function readFile(id){ const el = $(id); if (!el.files || !el.files[0]) return null; return await el.files[0].text(); }

const SCANNER_PICK = [["pickNmap","Nmap"],["pickNessus","Nessus"],["pickOpenvas","OpenVAS"],["pickZap","OWASP ZAP"],["pickBurp","Burp Suite"],["pickQualys","Qualys"]];
function updateScannerBoxes(){ SCANNER_PICK.forEach(([pid, name]) => { const card = document.querySelector(`[data-card="${name}"]`); if (card) card.hidden = !($(""+pid) && $(""+pid).checked); }); const any = SCANNER_PICK.some(([pid]) => $(pid).checked); $("pickerHint").hidden = any; }
SCANNER_PICK.forEach(([pid]) => { const el = $(pid); if (el) el.addEventListener("change", updateScannerBoxes); });
updateScannerBoxes();
$("runTriage").onclick = async () => {
  const map = [["fileNmap","Nmap"],["fileNessus","Nessus"],["fileOpenvas","OpenVAS"],["fileZap","OWASP ZAP"],["fileBurp","Burp Suite"],["fileQualys","Qualys"]].filter(([id, name]) => { const pick = SCANNER_PICK.find(([, n]) => n === name); return pick && $(pick[0]).checked; });
  if (!map.length) { $("triageStatus").textContent = "Choose at least one scanner above first."; return; }
  const files = [];
  for (const [id, scanner] of map) { const content = await readFile(id); if (content) files.push({ scanner, content }); }
  if (!files.length) { $("triageStatus").textContent = "Upload at least one file."; return; }
  const r = await api("/api/scans", { method: "POST", body: JSON.stringify({ name: $("scanName").value || "Scan", files }) });
  currentScanId = r.scanId; currentFindings = r.findings; $("triageStatus").textContent = `Triage complete: ${r.findings.length} findings.`; renderFindings(currentFindings); loadDashboard();
};
async function loadDemo(kind){ const r = await api(`/api/demo/${kind}`, { method: "POST", body: "{}" }); currentScanId = r.scanId; currentFindings = r.findings; $("triageStatus").textContent = `Demo loaded: ${r.findings.length} findings.`; renderFindings(currentFindings); loadDashboard(); }
async function loadReviewerDemo(){ await loadDemo("before"); await loadDemo("after"); $("triageStatus").textContent = "Reviewer demo loaded: before (7 findings) and after (3 findings) — compare them in Compare."; }
$("demoReviewer").onclick = loadReviewerDemo; const rdb = $("reviewerDemoBtn"); if (rdb) rdb.onclick = loadReviewerDemo;
$("demoSample").onclick = () => loadDemo("before"); $("demoScanners").onclick = () => loadDemo("scanners");
$("pasteToggle").onclick = () => { $("pastePanel").hidden = !$("pastePanel").hidden; };
$("pasteRun").onclick = async () => { const content = $("pasteText").value.trim(); if (!content) { $("triageStatus").textContent = "Paste scan text first."; return; } const r = await api("/api/scans", { method: "POST", body: JSON.stringify({ name: $("scanName").value || "Pasted scan", files: [{ scanner: "Nmap", content }] }) }); currentScanId = r.scanId; currentFindings = r.findings; $("triageStatus").textContent = `Triage complete: ${r.findings.length} findings.`; renderFindings(currentFindings); loadDashboard(); };
$("runCompare").onclick = async () => { if (!$("compareA").value || !$("compareB").value || $("compareA").value === $("compareB").value) { $("compareOut").innerHTML = "<p>Pick two different scans to compare.</p>"; return; } const r = await api(`/api/compare?a=${$("compareA").value}&b=${$("compareB").value}`); const list = (arr) => arr.map((f) => `<li>${esc(f.host)}:${f.port} ${esc(f.service)} — ${esc(f.severity)} ${f.score}</li>`).join("") || "<li>None.</li>"; $("compareOut").innerHTML = `<div class="compare-grid"><div class="compare-card"><b>${r.new.length}</b>New<ul>${list(r.new)}</ul></div><div class="compare-card"><b>${r.resolved.length}</b>Resolved<ul>${list(r.resolved)}</ul></div><div class="compare-card"><b>${r.stillOpen.length}</b>Still open<ul>${list(r.stillOpen)}</ul></div></div>`; };
function download(name, content, type){ const a = document.createElement("a"); a.href = URL.createObjectURL(new Blob([content], { type })); a.download = name; a.click(); }
async function exportFile(fmt){ if (!currentScanId) return; const r = await fetch(`/api/export/${currentScanId}?format=${fmt}`, { headers: { Authorization: `Bearer ${token}` } }); const blob = await r.blob(); const a = document.createElement("a"); a.href = URL.createObjectURL(blob); a.download = `report.${fmt === "md" ? "md" : fmt}`; a.click(); }
$("exportMd").onclick = () => exportFile("md"); $("exportCsv").onclick = () => exportFile("csv"); $("exportJson").onclick = () => exportFile("json");
const PLATFORM = {
  Features: "Six scanner imports, ranked triage, dashboard, board, compare, and exports.",
  Workflow: "Upload -> triage -> review breakdown -> move on board -> compare -> export.",
  "Why CullSec": "One ranked list instead of six separate reports, with transparent scoring.",
  Ecosystem: "Nmap, Nessus, OpenVAS, ZAP, Burp, and Qualys imports.",
  Methodology: "Contextual scoring v2: service base + version + scanner severity + exposure + asset criticality + host context, capped at 100, deterministic, not AI.",
  "Get Started": "Sign in, upload a scan, review the ranked list, and export a report.",
  Security: "Passwords are hashed server-side. Nothing is sent to external services by this app.",
  Roadmap: "Now live: six imports, board, compare, exports. Later: scheduled scans, more formats, richer host views.",
  Glossary: "Triage: ranking findings by risk. Dedupe: removing duplicate findings for the same host, port, and service.",
  Changelog: "v1: local TypeScript fullstack rebuild with SQLite, six imports, scoring v2, board, compare, exports and demo packs.",
  FAQ: "Is scoring AI? No, it is deterministic and rule-based. Is data sent anywhere? No."
};
const PLATFORM_PAGES = {
  Workflow: `<p class="so-plat-kicker blue">PLATFORM</p><h2>From scan file to fix list, in five steps</h2><p class="so-plat-intro">No new scanner, no agent, no extra service. CullSec triages what your scanners already found.</p><div class="so-feature-grid">
<article class="so-feature"><h3>1 · Upload</h3><p>Upload Nmap, Nessus, OpenVAS/GVM, ZAP, Burp or Qualys output — one file, or a mix. Only scan systems you own or are authorised to test.</p></article>
<article class="so-feature"><h3>2 · Score &amp; dedupe</h3><p>Every finding gets a deterministic 0–100 score and a stored breakdown. Duplicates for the same host, port and service merge into one ranked finding.</p></article>
<article class="so-feature"><h3>3 · Review the breakdown</h3><p>Tap “Why this score?” on any finding to see base, risky service, version, scanner severity, exposure, asset criticality and host context, factor by factor.</p></article>
<article class="so-feature"><h3>4 · Fix on the board</h3><p>Move findings Open → In progress → Fixed, or mark Risk accepted / False positive. Status is saved under your account, per scan and across scans.</p></article>
<article class="so-feature"><h3>5 · Compare &amp; export</h3><p>Re-scan, compare before and after, and download Markdown, CSV or JSON. The diff is the proof that a fix worked.</p></article>
</div>`,
  "Why CullSec": `<p class="so-plat-kicker blue">PLATFORM</p><h2>One ranked list, instead of six separate reports</h2><p class="so-plat-intro">Scanners are good at finding. They are bad at telling you what to fix first. CullSec adds the ranking, the explanation and the workflow.</p><div class="so-feature-grid">
<article class="so-feature"><h3>Fix order is reading order</h3><p>Cleartext Telnet, exposed databases and known-bad versions float to the top. Lower-risk findings sit below them, not beside them as equals.</p></article>
<article class="so-feature"><h3>Transparent, not a black box</h3><p>Every score shows its parts. If you disagree with a rank, you can see exactly which factor pushed it up — and fix that thing first.</p></article>
<article class="so-feature"><h3>Local, saved, portable</h3><p>Your account, scans and progress live in one local SQLite file. Reports download as Markdown, CSV or JSON, ending with “Built by ADYREX”.</p></article>
<article class="so-feature"><h3>What CullSec is not</h3><p>Not AI scoring — scoring is deterministic and rule-based. Not a scanner — it triages scanner output. Not a public link — this build is private to your account.</p></article></div>`,
  Ecosystem: `<p class="so-plat-kicker blue">PLATFORM</p><h2>Six scanners in, one ranked list out</h2><p class="so-plat-intro">Upload any mix. Cross-scanner dedupe is by host, port and service, keeping the named issue from whichever scanner found it.</p><div class="panel"><h3>Scanner imports</h3><div class="row-list">
<div class="row"><strong>Nmap</strong><span class="meta">XML · nmap -sV -oX scan.xml</span></div>
<div class="row"><strong>Nessus</strong><span class="meta">CSV · Export → CSV</span></div>
<div class="row"><strong>OpenVAS / GVM</strong><span class="meta">XML · GVM report download, XML format</span></div>
<div class="row"><strong>OWASP ZAP</strong><span class="meta">JSON / XML · Report → Generate report</span></div>
<div class="row"><strong>Burp Suite</strong><span class="meta">XML · Issues → Save / export XML</span></div>
<div class="row"><strong>Qualys</strong><span class="meta">CSV / XML · Qualys report, CSV or XML format</span></div></div></div>
`,
  Methodology: `<p class="so-plat-kicker blue">PLATFORM</p><h2>Contextual scoring v2 — deterministic, not AI</h2><p class="so-plat-intro">Score = base 10 + risky service + known-bad version + scanner severity + exposure + asset criticality + host context, capped at 100. The full breakdown is stored per finding.</p><div class="panel"><h3>The eight parts</h3><div class="row-list">
<div class="row"><strong>Base</strong><span class="meta">10</span></div>
<div class="row"><strong>Risky service (by port)</strong><span class="meta">Telnet 70 · Redis / MongoDB 60 · SMB / MSSQL / MySQL / PostgreSQL / VNC 50 · FTP 40</span></div>
<div class="row"><strong>Known-bad version</strong><span class="meta">+25 when a version hint matches, e.g. Apache 2.4.49, vsftpd 2.3.4</span></div>
<div class="row"><strong>Scanner severity</strong><span class="meta">Critical 30 · High 20 · Medium 10 · Low 5 · Info 0</span></div>
<div class="row"><strong>Exposure</strong><span class="meta">+5 for cleartext protocols (Telnet, FTP)</span></div>
<div class="row"><strong>Asset criticality</strong><span class="meta">+5 for database / cache services</span></div>
<div class="row"><strong>Host context</strong><span class="meta">+3 when a host has 3 or more findings</span></div>
<div class="row"><strong>Total</strong><span class="meta">Capped at 100</span></div></div></div>
<div class="panel"><h3>Severity bands from score</h3><div class="row-list">
<div class="row"><strong>Critical</strong><span class="meta">85–100</span></div>
<div class="row"><strong>High</strong><span class="meta">65–84</span></div>
<div class="row"><strong>Medium</strong><span class="meta">40–64</span></div>
<div class="row"><strong>Low</strong><span class="meta">15–39</span></div>
<div class="row"><strong>Info</strong><span class="meta">0–14</span></div></div><p>Dedupe: findings for the same host, port and service merge into one. Scoring is never claimed as AI — it is the formula above, every time.</p></div>`,
  Roadmap: `<p class="so-plat-kicker blue">PLATFORM</p><h2>Roadmap — live now, later</h2><div class="panel"><h3>Live now</h3><p>Six scanner imports, merged ranked triage, contextual scoring v2 with breakdowns, executive dashboard, findings explorer, remediation board, scan comparison, Markdown / CSV / JSON exports, reviewer demo.</p></div><div class="panel"><h3>Later</h3><p>Scheduled scans, more scanner formats, and richer host inventory views — only if they keep scoring transparent and data local.</p></div>`,
  Glossary: `<p class="so-plat-kicker blue">PLATFORM</p><h2>Glossary</h2><div class="panel"><div class="row-list">
<div class="row"><strong>Triage</strong><span class="meta">Ranking findings by risk, so the fix order is clear</span></div>
<div class="row"><strong>Finding</strong><span class="meta">One host + port + service issue from a scan</span></div>
<div class="row"><strong>Dedupe</strong><span class="meta">Merging duplicate findings for the same host, port and service</span></div>
<div class="row"><strong>Contextual scoring v2</strong><span class="meta">Deterministic 0–100 score from service, version, scanner severity, exposure, asset and host context</span></div>
<div class="row"><strong>Board</strong><span class="meta">Findings grouped by status: Open, In progress, Fixed, Risk accepted, False positive</span></div>
<div class="row"><strong>Compare</strong><span class="meta">Diffing two scans: new, resolved, still open</span></div>
</div></div>`,
  Changelog: `<p class="so-plat-kicker blue">PLATFORM</p><h2>Changelog</h2><div class="panel"><div class="row-list">
<div class="row"><strong>Fullstack rebuild</strong><span class="meta">TypeScript + Node.js backend, SQLite database, saved accounts, six imports, scoring v2, board, compare, exports and demo packs</span></div>
<div class="row"><strong>Screen 1 rebuild</strong><span class="meta">Scrollytelling first page: hero, chapters 01–05, sign-in, reviewer walkthrough, Platform</span></div>
<div class="row"><strong>Signed-in pages</strong><span class="meta">Overview, Triage, Board, Compare and Platform rebuilt to match the reference screenshots</span></div>
<div class="row"><strong>Platform pages</strong><span class="meta">Full Workflow, Why CullSec, Ecosystem, Methodology, Get started, Security, Roadmap, Glossary, Changelog and FAQ pages, not summaries</span></div></div></div>`,
  FAQ: `<p class="so-plat-kicker blue">PLATFORM</p><h2>Frequently asked questions</h2><div class="panel"><div class="row-list">
<div class="row"><strong>Is scoring AI?</strong><span class="meta">No. It is deterministic and rule-based — the formula is on the Methodology page.</span></div>

<div class="row"><strong>Is there a public link?</strong><span class="meta">No. This build runs locally and is private to your account.</span></div>
<div class="row"><strong>Is my scan data sent anywhere?</strong><span class="meta">No. Data lives in a local SQLite file and this app makes no outbound call with it.</span></div>
<div class="row"><strong>What if I enter the wrong password?</strong><span class="meta">Sign-in is rejected. Use the password you set on first sign-in; the strong-password rule applies only to new accounts.</span></div>
<div class="row"><strong>Can I delete a scan?</strong><span class="meta">Yes — in Triage, Saved scans, tap Delete next to a scan. Its findings are deleted with it.</span></div></div></div>`
};
PLATFORM_PAGES["Get started"] = PLATFORM_PAGES["Get Started"];
function renderPlatform(){
  const nav = $("platformNav"); if (!nav) return;
  nav.innerHTML = Object.keys(PLATFORM).map((k) => `<button type="button" class="so-plat-btn" data-p="${k}">${k}</button>`).join("");
  const show = (k) => {
    $("siNowLabel").textContent = k.toUpperCase();
    if (k === "Features") { const src = $("soPlatformContent"); $("platformContent").innerHTML = src ? src.innerHTML : `<h3>Features</h3><p>${PLATFORM.Features}</p>`; }
    else $("platformContent").innerHTML = PLATFORM_PAGES[k] || `<p class="so-plat-kicker blue">PLATFORM</p><h2>${k}</h2><p class="so-plat-intro">${PLATFORM[k]}</p>`;
    nav.querySelectorAll("button").forEach((x) => x.classList.toggle("active", x.dataset.p === k));
  };
  show("Features"); nav.querySelectorAll("button").forEach((b) => b.onclick = () => show(b.dataset.p));
}
/* Signed-out Platform switcher (signed-out page only; signed-in Platform uses renderPlatform). */
(function(){
  const nav = $("soPlatformNav"); if (!nav) return;
  const content = $("soPlatformContent"); const label = $("soNowLabel");
  const featuresHTML = content ? content.innerHTML : "";
  const SO_TEXT = {
    Workflow: "Upload -> triage -> review breakdown -> move on board -> compare -> export.",
    "Why CullSec": "One ranked list instead of six separate reports, with transparent scoring.",
    Ecosystem: "Nmap, Nessus, OpenVAS, ZAP, Burp, and Qualys imports.",
    Methodology: "Contextual scoring v2: service base + version + scanner severity + exposure + asset criticality + host context, capped at 100, deterministic, not AI.",
    "Get started": "Sign in, upload a scan, review the ranked list, and export a report.",
    Security: "Passwords are hashed server-side. Nothing is sent to external services by this app.",
    Roadmap: "Now live: six imports, board, compare, exports. Later: scheduled scans, more formats, richer host views.",
    Glossary: "Triage: ranking findings by risk. Dedupe: removing duplicate findings for the same host, port, and service.",
    Changelog: "Local TypeScript fullstack rebuild with SQLite, six imports, scoring v2, board, compare, exports and demo packs.",
    FAQ: "Is scoring AI? No, it is deterministic and rule-based. Is data sent anywhere? No."
  };
  nav.querySelectorAll(".so-plat-btn").forEach((b) => b.onclick = () => {
    nav.querySelectorAll(".so-plat-btn").forEach((x) => x.classList.toggle("active", x === b));
    if (label) label.textContent = b.dataset.soplat.toUpperCase();
    if (b.dataset.soplat === "Features") { content.innerHTML = featuresHTML; return; }
    content.innerHTML = (typeof PLATFORM_PAGES !== "undefined" && PLATFORM_PAGES[b.dataset.soplat]) || `<p class="so-plat-kicker blue">PLATFORM</p><h2>${b.dataset.soplat}</h2><p class="so-plat-intro">${SO_TEXT[b.dataset.soplat] || ""}</p>`;
  });
})();
(function(){
  const btn = $("walkthroughBtn"); const panel = $("walkthroughPanel"); if (!btn || !panel) return;
  btn.onclick = () => { panel.hidden = !panel.hidden; btn.textContent = panel.hidden ? "Show the 2-minute walkthrough" : "Hide the 2-minute walkthrough"; };
})();
if (token) showSignedIn(true);

document.querySelectorAll(".goto-tab").forEach((b) => b.onclick = () => { const tb = document.querySelector(`[data-tab="${b.dataset.goto}"]`); if (tb) tb.click(); });
