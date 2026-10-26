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
  $("signedOut").hidden = show; $("signedIn").hidden = !show; $("signOut").hidden = !show; $("editProfile").hidden = !show; $("signedInUser").hidden = !show; if ($("globalFooter")) $("globalFooter").hidden = !show; window.scrollTo(0, 0);
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
$("signinForm").addEventListener("submit", async (e) => {
  e.preventDefault(); $("signinError").textContent = "";
  try {
    const r = await fetch("/api/signin", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ name: $("name").value, email: $("email").value, password: $("password").value }) });
    const j = await r.json(); if (!r.ok) throw new Error(j.error || "Sign-in failed");
    token = j.token; localStorage.setItem("cullsec-token", token); setSignedInUser(j.account); showSignedIn(true);
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
    $("savedScansList").querySelectorAll("[data-open]").forEach((b) => b.onclick = async () => { const sc = await api(`/api/scans/${b.dataset.open}`); currentScanId = sc.scan.id; currentFindings = sc.findings; renderFindings(currentFindings); document.querySelector('[data-tab="triage"]').click(); });
    $("savedScansList").querySelectorAll("[data-del]").forEach((b) => b.onclick = async () => { if (!confirm(`Delete this scan and its findings?`)) return; await api(`/api/scans/${b.dataset.del}`, { method: "DELETE" }); if (String(currentScanId) === b.dataset.del) { currentScanId = null; currentFindings = []; } loadDashboard(); });
    $("compareEmpty").hidden = d.scans.length >= 2; $("boardEmpty").hidden = d.scans.length > 0;
    const sev = d.severity || {};
    const total = d.total || 0;
    const fixed = (d.status && d.status.Fixed) || 0;
    const progress = total ? Math.round((fixed / total) * 100) : 0;
    const statCard = (label, num, sub, cls) => `<div class="stat ${cls || ""}"><div class="stat-label">${label}</div><div class="stat-num">${num}</div><div class="stat-sub">${sub}</div></div>`;
    $("stats").innerHTML = `<div class="stat-grid">${statCard("Total findings", total, `${d.scans.length} saved scans`, "")}${statCard("Critical", sev.Critical || 0, "Fix first", "critical")}${statCard("High", sev.High || 0, "Fix next", "high")}${statCard("Medium", sev.Medium || 0, "Plan a fix", "medium")}${statCard("Low", sev.Low || 0, "Lower priority", "low")}${statCard("Info", sev.Info || 0, "For reference", "info")}</div><div class="panel"><h3>Remediation progress</h3><p>${fixed} of ${total} fixed · ${progress}%</p><div class="progress-track"><div class="progress-fill" style="width:${progress}%"></div></div><p>${Object.entries(d.status || {}).map(([k, v]) => `<span class="chip chip-status">${esc(k)}: ${v}</span>`).join(" ") || "No findings yet."}</p></div>`;
    $("scanSummary").innerHTML = `<div class="panel"><h3>Per-scan summary</h3><div class="row-list">${d.perScan.map((s) => `<div class="row"><div><strong>${esc(s.name)}</strong><div class="meta">${s.total} findings</div></div><div class="meta">${s.critical} critical · ${s.fixed} fixed</div></div>`).join("") || "<p>No scans yet.</p>"}</div></div>`;
    $("riskyHosts").innerHTML = `<div class="row-list">${d.riskiestHosts.map((h) => `<div class="row"><strong>${esc(h.host)}</strong><span class="meta">${h.count} findings · max ${h.max}</span></div>`).join("") || "<p>No hosts yet.</p>"}</div>`;
    const maxSvc = Math.max(1, ...(d.commonServices || []).map((s) => s.count));
    $("commonServices").innerHTML = `<div class="row-list">${d.commonServices.map((s) => `<div class="row"><strong>${esc(s.service)}</strong><span style="display:flex;gap:10px;align-items:center"><span class="mini-bar"><i style="width:${Math.round((s.count / maxSvc) * 100)}%"></i></span><span class="meta">${s.count}</span></span></div>`).join("") || "<p>No services yet.</p>"}</div>`;
    $("trend").innerHTML = `<div class="row-list">${d.trend.map((t) => `<div class="row"><strong>${esc(t.name)}</strong><span class="meta">${t.total} findings · ${t.critical} critical · avg ${t.avg}</span></div>`).join("") || "<p>No scans yet.</p>"}</div>`;
    $("hostInventory").innerHTML = `<div class="row-list">${d.hostInventory.map((h) => `<div class="row"><div><strong>${esc(h.host)}</strong><div class="meta">${esc(h.services)}</div></div><span class="meta">max ${h.maxScore}</span></div>`).join("") || "<p>No hosts yet.</p>"}</div>`;
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
  $("findingsList").innerHTML = out.map((f) => `<div class="finding sev-${f.severity}"><div class="finding-head"><span><span class="chip ${sevClass(f.severity)}">${esc(f.severity)}</span> <span class="chip chip-status">${esc(f.status)}</span></span><span class="score-badge">${f.score}</span></div><div class="finding-title">${esc(f.host)}:${f.port} ${esc(f.service)}</div><div class="finding-meta">${esc(f.title || "")}${f.version ? ` · ${esc(f.version)}` : ""}${f.scanner ? ` · ${esc(f.scanner)}` : ""}</div><button type="button" onclick="showWhy(${f.id})">Why this score?</button></div>`).join("") || "<p>No findings match.</p>";
}
window.showWhy = (id) => { const f = currentFindings.find((x) => x.id === id); if (!f) return; const b = f.breakdown; const part = (label, v) => `<div><b>${v}</b><span>${label}</span></div>`; $("aiPanel").innerHTML = `<p><strong>Model not connected.</strong> Deterministic breakdown for ${esc(f.host)}:${f.port}.</p><div class="breakdown-grid">${part("Base", b.base)}${part("Risky service", b.riskyService)}${part("Version", b.version)}${part("Scanner severity", b.scannerSeverity)}${part("Exposure", b.exposure)}${part("Asset criticality", b.assetCriticality)}${part("Host context", b.hostContext)}${part("Total", b.total)}</div><p>${esc((b.reasons || []).join("; "))}</p>`; };
["searchBox","sevFilter","statusFilter","sortSelect"].forEach((id) => $(id).addEventListener("input", () => renderFindings(currentFindings)));
async function readFile(id){ const el = $(id); if (!el.files || !el.files[0]) return null; return await el.files[0].text(); }
$("runTriage").onclick = async () => {
  const map = [["fileNmap","Nmap"],["fileNessus","Nessus"],["fileOpenvas","OpenVAS"],["fileZap","OWASP ZAP"],["fileBurp","Burp Suite"],["fileQualys","Qualys"]];
  const files = [];
  for (const [id, scanner] of map) { const content = await readFile(id); if (content) files.push({ scanner, content }); }
  if (!files.length) { $("triageStatus").textContent = "Upload at least one file."; return; }
  const r = await api("/api/scans", { method: "POST", body: JSON.stringify({ name: $("scanName").value || "Scan", files }) });
  currentScanId = r.scanId; currentFindings = r.findings; $("triageStatus").textContent = `Triage complete: ${r.findings.length} findings.`; renderFindings(currentFindings); loadDashboard();
};
async function loadDemo(kind){ const r = await api(`/api/demo/${kind}`, { method: "POST", body: "{}" }); currentScanId = r.scanId; currentFindings = r.findings; $("triageStatus").textContent = `Demo loaded: ${r.findings.length} findings.`; renderFindings(currentFindings); loadDashboard(); }
async function loadReviewerDemo(){ await loadDemo("before"); await loadDemo("after"); $("triageStatus").textContent = "Reviewer demo loaded: before (7 findings) and after (3 findings) — compare them in Compare."; }
$("demoReviewer").onclick = loadReviewerDemo; $("reviewerDemoBtn").onclick = loadReviewerDemo;
$("demoSample").onclick = () => loadDemo("before"); $("demoScanners").onclick = () => loadDemo("scanners");
$("pasteToggle").onclick = () => { $("pastePanel").hidden = !$("pastePanel").hidden; };
$("pasteRun").onclick = async () => { const content = $("pasteText").value.trim(); if (!content) { $("triageStatus").textContent = "Paste scan text first."; return; } const r = await api("/api/scans", { method: "POST", body: JSON.stringify({ name: $("scanName").value || "Pasted scan", files: [{ scanner: "Nmap", content }] }) }); currentScanId = r.scanId; currentFindings = r.findings; $("triageStatus").textContent = `Triage complete: ${r.findings.length} findings.`; renderFindings(currentFindings); loadDashboard(); };
$("runCompare").onclick = async () => { if (!$("compareA").value || !$("compareB").value || $("compareA").value === $("compareB").value) { $("compareOut").innerHTML = "<p>Pick two different scans to compare.</p>"; return; } const r = await api(`/api/compare?a=${$("compareA").value}&b=${$("compareB").value}`); const list = (arr) => arr.map((f) => `<li>${esc(f.host)}:${f.port} ${esc(f.service)} — ${esc(f.severity)} ${f.score}</li>`).join("") || "<li>None.</li>"; $("compareOut").innerHTML = `<div class="compare-grid"><div class="compare-card"><b>${r.new.length}</b>New<ul>${list(r.new)}</ul></div><div class="compare-card"><b>${r.resolved.length}</b>Resolved<ul>${list(r.resolved)}</ul></div><div class="compare-card"><b>${r.stillOpen.length}</b>Still open<ul>${list(r.stillOpen)}</ul></div></div>`; };
$("downloadJira").onclick = () => { const csv = "Summary,Host,Port,Severity,Score\n" + currentFindings.map((f) => `"${f.title}",${f.host},${f.port},${f.severity},${f.score}`).join("\n"); download("jira-import.csv", csv, "text/csv"); };
$("downloadGithub").onclick = () => { const txt = currentFindings.map((f) => `## ${f.title} — ${f.host}:${f.port}\nSeverity: ${f.severity}, Score: ${f.score}, Status: ${f.status}\n`).join("\n"); download("github-issues.md", txt, "text/markdown"); };
$("previewAlerts").onclick = () => { const payload = { text: `CullSec alert: ${currentFindings.filter((f) => f.severity === "Critical" || f.severity === "High").length} Critical/High findings`, findings: currentFindings.slice(0, 5) }; $("alertPreview").textContent = "Slack / Teams payload preview (generator only, not sent):\n" + JSON.stringify(payload, null, 2); };
function download(name, content, type){ const a = document.createElement("a"); a.href = URL.createObjectURL(new Blob([content], { type })); a.download = name; a.click(); }
async function exportFile(fmt){ if (!currentScanId) return; const r = await fetch(`/api/export/${currentScanId}?format=${fmt}`, { headers: { Authorization: `Bearer ${token}` } }); const blob = await r.blob(); const a = document.createElement("a"); a.href = URL.createObjectURL(blob); a.download = `report.${fmt === "md" ? "md" : fmt}`; a.click(); }
$("exportMd").onclick = () => exportFile("md"); $("exportCsv").onclick = () => exportFile("csv"); $("exportJson").onclick = () => exportFile("json");
$("portfolioBtn").onclick = async () => { const r = await fetch("/api/portfolio", { headers: { Authorization: `Bearer ${token}` } }); const blob = await r.blob(); const a = document.createElement("a"); a.href = URL.createObjectURL(blob); a.download = "portfolio-pack.md"; a.click(); };
async function saveOne(provider, payload, label){ await api("/api/settings", { method: "POST", body: JSON.stringify({ [provider]: payload }) }); const s = await api("/api/settings"); $("settingsStatus").textContent = `${label} saved. Only masked hints are returned. Nothing was sent anywhere.`; $("settingsSaved").innerHTML = `<pre>${esc(JSON.stringify(s.settings, null, 2))}</pre>`; }
$("saveJira").onclick = () => saveOne("jira", { site: $("setJiraSite").value, project: $("setJiraProject").value, secret: $("setJiraSecret").value }, "Jira settings");
$("saveGithub").onclick = () => saveOne("github", { repo: $("setGithubRepo").value, secret: $("setGithubSecret").value }, "GitHub settings");
$("saveSlack").onclick = () => saveOne("slack", { site: $("setSlackChannel").value, secret: $("setSlack").value }, "Slack settings");
$("saveTeams").onclick = () => saveOne("teams", { site: $("setTeamsChannel").value, secret: $("setTeams").value }, "Teams settings");
$("saveModel").onclick = () => saveOne("model", { site: $("setModelName").value, secret: $("setModel").value }, "AI model settings");
$("disconnectJira").onclick = () => saveOne("jira", { site: "", project: "", secret: "" }, "Jira disconnected");
$("disconnectGithub").onclick = () => saveOne("github", { repo: "", secret: "" }, "GitHub disconnected");
$("disconnectSlack").onclick = () => saveOne("slack", { site: "", secret: "" }, "Slack disconnected");
$("disconnectTeams").onclick = () => saveOne("teams", { site: "", secret: "" }, "Teams disconnected");
$("disconnectModel").onclick = () => saveOne("model", { site: "", secret: "" }, "AI model disconnected");
const PLATFORM = {
  Features: "Six scanner imports, ranked triage, dashboard, board, compare, exports, and settings.",
  Workflow: "Upload -> triage -> review breakdown -> move on board -> compare -> export.",
  "Why CullSec": "One ranked list instead of six separate reports, with transparent scoring.",
  Ecosystem: "Nmap, Nessus, OpenVAS, ZAP, Burp, and Qualys imports; Jira/GitHub/Slack/Teams generators.",
  Methodology: "Contextual scoring v2: service base + version + scanner severity + exposure + asset criticality + host context, capped at 100, deterministic, not AI.",
  Portfolio: "Architecture, README text, CV blurb, timed 2-minute demo script, downloadable as one Markdown file — use the Download portfolio pack button in Triage.",
  "Get Started": "Sign in, upload a scan, review the ranked list, and export a report.",
  Security: "Passwords are hashed server-side. Secrets are hashed with only a masked hint returned. Nothing is sent to external services by this app.",
  Roadmap: "Now live: six imports, board, compare, exports. Next: live integrations with your tokens, model connection. Later: scheduled scans.",
  Glossary: "Triage: ranking findings by risk. Dedupe: removing duplicate findings for the same host, port, and service.",
  Changelog: "v1: local TypeScript fullstack rebuild with SQLite, six imports, scoring v2, board, compare, exports, settings, demo packs, and portfolio pack.",
  FAQ: "Is scoring AI? No, it is deterministic and rule-based. Are tickets live? No, generators until tokens are connected. Is data sent anywhere? No."
};
const PLATFORM_PAGES = {
  Workflow: `<p class="so-plat-kicker blue">PLATFORM</p><h2>From scan file to fix list, in five steps</h2><p class="so-plat-intro">No new scanner, no agent, no extra service. CullSec triages what your scanners already found.</p><div class="so-feature-grid">
<article class="so-feature"><h3>1 · Upload</h3><p>Upload Nmap, Nessus, OpenVAS/GVM, ZAP, Burp or Qualys output — one file, or a mix. Only scan systems you own or are authorised to test.</p></article>
<article class="so-feature"><h3>2 · Score &amp; dedupe</h3><p>Every finding gets a deterministic 0–100 score and a stored breakdown. Duplicates for the same host, port and service merge into one ranked finding.</p></article>
<article class="so-feature"><h3>3 · Review the breakdown</h3><p>Tap “Why this score?” on any finding to see base, risky service, version, scanner severity, exposure, asset criticality and host context, factor by factor.</p></article>
<article class="so-feature"><h3>4 · Fix on the board</h3><p>Move findings Open → In progress → Fixed, or mark Risk accepted / False positive. Status is saved under your account, per scan and across scans.</p></article>
<article class="so-feature"><h3>5 · Compare &amp; export</h3><p>Re-scan, compare before and after, and download Markdown, CSV or JSON. The diff is the proof that a fix worked.</p></article>
<article class="so-feature"><h3>Then tickets &amp; alerts</h3><p>Generate a Jira import CSV, a GitHub issues pack, or Slack / Teams payload previews from the same scan. Generators only — nothing is created or sent.</p></article></div>`,
  "Why CullSec": `<p class="so-plat-kicker blue">PLATFORM</p><h2>One ranked list, instead of six separate reports</h2><p class="so-plat-intro">Scanners are good at finding. They are bad at telling you what to fix first. CullSec adds the ranking, the explanation and the workflow.</p><div class="so-feature-grid">
<article class="so-feature"><h3>Fix order is reading order</h3><p>Cleartext Telnet, exposed databases and known-bad versions float to the top. Lower-risk findings sit below them, not beside them as equals.</p></article>
<article class="so-feature"><h3>Transparent, not a black box</h3><p>Every score shows its parts. If you disagree with a rank, you can see exactly which factor pushed it up — and fix that thing first.</p></article>
<article class="so-feature"><h3>Local, saved, portable</h3><p>Your account, scans and progress live in one local SQLite file. Reports download as Markdown, CSV or JSON, ending with “Built by ADYREX”.</p></article>
<article class="so-feature"><h3>What CullSec is not</h3><p>Not AI scoring — scoring is deterministic and rule-based. Not live posting — tickets and alerts are generators until you connect tokens. Not a scanner — it triages scanner output. Not a public link — this build is private to your account.</p></article></div>`,
  Ecosystem: `<p class="so-plat-kicker blue">PLATFORM</p><h2>Six scanners in, one ranked list out</h2><p class="so-plat-intro">Upload any mix. Cross-scanner dedupe is by host, port and service, keeping the named issue from whichever scanner found it.</p><div class="panel"><h3>Scanner imports</h3><div class="row-list">
<div class="row"><strong>Nmap</strong><span class="meta">XML · nmap -sV -oX scan.xml</span></div>
<div class="row"><strong>Nessus</strong><span class="meta">CSV · Export → CSV</span></div>
<div class="row"><strong>OpenVAS / GVM</strong><span class="meta">XML · GVM report download, XML format</span></div>
<div class="row"><strong>OWASP ZAP</strong><span class="meta">JSON / XML · Report → Generate report</span></div>
<div class="row"><strong>Burp Suite</strong><span class="meta">XML · Issues → Save / export XML</span></div>
<div class="row"><strong>Qualys</strong><span class="meta">CSV / XML · Qualys report, CSV or XML format</span></div></div></div>
<div class="panel"><h3>Ticket &amp; alert generators — live needs your token</h3><div class="row-list">
<div class="row"><strong>Jira import CSV</strong><span class="meta">Generator · per scan</span></div>
<div class="row"><strong>GitHub issues pack</strong><span class="meta">Generator · Markdown, per finding</span></div>
<div class="row"><strong>Slack webhook payload</strong><span class="meta">Generator · preview only, not sent</span></div>
<div class="row"><strong>Microsoft Teams payload</strong><span class="meta">Generator · MessageCard preview only, not sent</span></div></div></div>`,
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
<div class="row"><strong>Info</strong><span class="meta">0–14</span></div></div><p>Dedupe: findings for the same host, port and service merge into one. The AI panel always says “Model not connected” until you add your own model key in Settings — it never claims AI scoring.</p></div>`,
  Portfolio: `<p class="so-plat-kicker blue">PLATFORM</p><h2>Portfolio pack — one Markdown download</h2><p class="so-plat-intro">The same pack reviewers get: architecture, README text, CV blurb and a timed demo script, in one file.</p><div class="so-feature-grid">
<article class="so-feature"><h3>Architecture</h3><p>Local TypeScript fullstack app: static HTML/CSS/JavaScript frontend served by a Node.js TypeScript backend, with a file-backed SQLite database. No data is sent to external services by this app.</p></article>
<article class="so-feature"><h3>README (short)</h3><p>CullSec turns raw scanner output into a prioritised fix list. Upload six scanner formats, get one ranked triage, move findings on a board, compare scans, and export Markdown, CSV or JSON.</p></article>
<article class="so-feature"><h3>CV blurb (copy-ready)</h3><p>Built CullSec, a local vulnerability triage platform: six scanner imports merged into one ranked triage, deterministic contextual scoring with per-finding breakdowns, remediation board and scan comparison, and Markdown/CSV/JSON exports, using TypeScript, Node.js, and SQLite.</p></article>
<article class="so-feature"><h3>Timed 2-minute demo script</h3><p>0:00 Sign in and show the dashboard. 0:20 Upload a scan, show the ranked list and a “Why this score?” breakdown. 0:50 Move a finding on the Board to Fixed. 1:10 Compare before and after scans (7 findings to 3). 1:30 Show a ticket generator preview and an export. 1:50 Close: local, deterministic scoring, no external data sent.</p></article></div><div class="action-row"><button id="portfolioBtn2" type="button" class="primary">Download portfolio pack</button></div>`,
  "Get Started": `<p class="so-plat-kicker blue">PLATFORM</p><h2>Get started in five minutes</h2><p class="so-plat-intro">No separate sign-up step. The first sign-in saves your account; the same email and password bring it back.</p><div class="so-feature-grid">
<article class="so-feature"><h3>1 · Sign in</h3><p>Enter a name (first time only), email and a strong password: 8+ characters with a lowercase letter, an uppercase letter, a number and a symbol.</p></article>
<article class="so-feature"><h3>2 · Try the sample</h3><p>In Triage, tap “Load my sample scan” to see a ranked list instantly, with no scan file needed.</p></article>
<article class="so-feature"><h3>3 · Run your own scan</h3><p>Scan a system you own or are authorised to test, export it in a supported format, and upload it in Triage.</p></article>
<article class="so-feature"><h3>4 · Work the board, then compare</h3><p>Move findings to Fixed, re-scan, compare the two scans, and download the report as evidence.</p></article></div><p>Run locally: npm install, then npm run dev, then open http://localhost:3000.</p>`,
  Security: `<p class="so-plat-kicker blue">PLATFORM</p><h2>Security &amp; privacy — what is stored, and what is not sent</h2><div class="so-feature-grid">
<article class="so-feature"><h3>Passwords, hashed</h3><p>Passwords are hashed server-side with scrypt and a per-account salt. They are never stored in plaintext, and never shown back.</p></article>
<article class="so-feature"><h3>Secrets, hashed with a hint only</h3><p>Integration and model secrets saved in Settings are hashed server-side. Only a masked last-4 hint is returned. Nothing is posted anywhere by this build.</p></article>
<article class="so-feature"><h3>Your data stays local</h3><p>Accounts, scans, findings and workflow status live in a local SQLite file (data/cullsec.db). This app makes no outbound call with your scan data.</p></article>
<article class="so-feature"><h3>Safe-use rule</h3><p>Scan only systems you own or are authorised to test. Demo data is fictional lab hosts (10.0.5.x) and is clearly labelled fictional.</p></article></div>`,
  Roadmap: `<p class="so-plat-kicker blue">PLATFORM</p><h2>Roadmap — live now, next, later</h2><div class="panel"><h3>Live now</h3><p>Six scanner imports, merged ranked triage, contextual scoring v2 with breakdowns, executive dashboard, findings explorer, remediation board, scan comparison, Markdown / CSV / JSON exports, ticket &amp; alert generators, Settings with hashed secrets, reviewer demo and portfolio pack.</p></div><div class="panel"><h3>Next — needs your tokens</h3><p>Live Jira issue creation, live GitHub issue creation, live Slack / Teams posting, and live AI explanations — each switched on only after you save your own token or webhook in Settings. Until then, generators and “Model not connected” are the honest labels.</p></div><div class="panel"><h3>Later</h3><p>Scheduled scans, more scanner formats, and richer host inventory views — only if they keep scoring transparent and data local.</p></div>`,
  Glossary: `<p class="so-plat-kicker blue">PLATFORM</p><h2>Glossary</h2><div class="panel"><div class="row-list">
<div class="row"><strong>Triage</strong><span class="meta">Ranking findings by risk, so the fix order is clear</span></div>
<div class="row"><strong>Finding</strong><span class="meta">One host + port + service issue from a scan</span></div>
<div class="row"><strong>Dedupe</strong><span class="meta">Merging duplicate findings for the same host, port and service</span></div>
<div class="row"><strong>Contextual scoring v2</strong><span class="meta">Deterministic 0–100 score from service, version, scanner severity, exposure, asset and host context</span></div>
<div class="row"><strong>Board</strong><span class="meta">Findings grouped by status: Open, In progress, Fixed, Risk accepted, False positive</span></div>
<div class="row"><strong>Compare</strong><span class="meta">Diffing two scans: new, resolved, still open</span></div>
<div class="row"><strong>Generator</strong><span class="meta">A downloadable preview (CSV, pack or payload) — nothing created or sent</span></div></div></div>`,
  Changelog: `<p class="so-plat-kicker blue">PLATFORM</p><h2>Changelog</h2><div class="panel"><div class="row-list">
<div class="row"><strong>Fullstack rebuild</strong><span class="meta">TypeScript + Node.js backend, SQLite database, saved accounts, six imports, scoring v2, board, compare, exports, settings, demo packs, portfolio pack</span></div>
<div class="row"><strong>Screen 1 rebuild</strong><span class="meta">Scrollytelling first page: hero, chapters 01–05, sign-in, reviewer walkthrough, Platform</span></div>
<div class="row"><strong>Signed-in pages</strong><span class="meta">Overview, Triage, Board, Compare, Platform and Settings rebuilt to match the reference screenshots</span></div>
<div class="row"><strong>Platform pages</strong><span class="meta">Full Workflow, Why CullSec, Ecosystem, Methodology, Portfolio, Get started, Security, Roadmap, Glossary, Changelog and FAQ pages, not summaries</span></div></div></div>`,
  FAQ: `<p class="so-plat-kicker blue">PLATFORM</p><h2>Frequently asked questions</h2><div class="panel"><div class="row-list">
<div class="row"><strong>Is scoring AI?</strong><span class="meta">No. It is deterministic and rule-based. The AI panel says “Model not connected” until you add your own key.</span></div>
<div class="row"><strong>Are Jira / GitHub / Slack / Teams live?</strong><span class="meta">No, not in this build. They are generators and payload previews until you connect tokens in Settings.</span></div>
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
    const dl = $("portfolioBtn2"); if (dl) dl.onclick = async () => { const r = await fetch("/api/portfolio", { headers: { Authorization: `Bearer ${token}` } }); const blob = await r.blob(); const a = document.createElement("a"); a.href = URL.createObjectURL(blob); a.download = "portfolio-pack.md"; a.click(); };
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
    Ecosystem: "Nmap, Nessus, OpenVAS, ZAP, Burp, and Qualys imports; Jira/GitHub/Slack/Teams generators.",
    Methodology: "Contextual scoring v2: service base + version + scanner severity + exposure + asset criticality + host context, capped at 100, deterministic, not AI.",
    Portfolio: "Architecture, README text, CV blurb, timed 2-minute demo script, downloadable as one Markdown file (signed-in Platform tab).",
    "Get started": "Sign in, upload a scan, review the ranked list, and export a report.",
    Security: "Passwords are hashed server-side. Secrets are hashed with only a masked hint returned. Nothing is sent to external services by this app.",
    Roadmap: "Now live: six imports, board, compare, exports. Next: live integrations with your tokens, model connection. Later: scheduled scans.",
    Glossary: "Triage: ranking findings by risk. Dedupe: removing duplicate findings for the same host, port, and service.",
    Changelog: "Local TypeScript fullstack rebuild with SQLite, six imports, scoring v2, board, compare, exports, settings, demo packs, and portfolio pack.",
    FAQ: "Is scoring AI? No, it is deterministic and rule-based. Are tickets live? No, generators until tokens are connected. Is data sent anywhere? No."
  };
  nav.querySelectorAll(".so-plat-btn").forEach((b) => b.onclick = () => {
    nav.querySelectorAll(".so-plat-btn").forEach((x) => x.classList.toggle("active", x === b));
    if (label) label.textContent = b.dataset.soplat.toUpperCase();
    if (b.dataset.soplat === "Features") { content.innerHTML = featuresHTML; return; }
    content.innerHTML = (typeof PLATFORM_PAGES !== "undefined" && PLATFORM_PAGES[b.dataset.soplat]) || `<p class="so-plat-kicker blue">PLATFORM</p><h2>${b.dataset.soplat}</h2><p class="so-plat-intro">${SO_TEXT[b.dataset.soplat] || ""}</p>`;
    const dl = $("portfolioBtn2"); if (dl) dl.onclick = () => { alert("Sign in to download the portfolio pack from Platform → Portfolio."); };
  });
})();
(function(){
  const btn = $("walkthroughBtn"); const panel = $("walkthroughPanel"); if (!btn || !panel) return;
  btn.onclick = () => { panel.hidden = !panel.hidden; btn.textContent = panel.hidden ? "Show the 2-minute walkthrough" : "Hide the 2-minute walkthrough"; };
})();
if (token) showSignedIn(true);
