import { createServer, IncomingMessage, ServerResponse } from "node:http";
import { readFileSync, existsSync } from "node:fs";
import { join, extname, normalize } from "node:path";
import { randomBytes, scryptSync, timingSafeEqual, createHash } from "node:crypto";
import { db } from "./db.js";
import { parseScanner, scoreAll } from "./parsers.js";
import { bandFromScore } from "./scoring.js";

const PORT = Number(process.env.PORT || 3000);
const PUBLIC = join(process.cwd(), "public");
type Account = { id: number; name: string; email: string; salt: string; password_hash: string };

function hashPassword(password: string, salt: string): string {
  return scryptSync(password, salt, 64).toString("hex");
}
function strongPassword(p: string): string | null {
  if (p.length < 8) return "Password must be at least 8 characters.";
  if (!/[a-z]/.test(p)) return "Password needs a lowercase letter (a-z).";
  if (!/[A-Z]/.test(p)) return "Password needs an uppercase letter (A-Z).";
  if (!/[0-9]/.test(p)) return "Password needs a number (0-9).";
  if (!/[^A-Za-z0-9]/.test(p)) return "Password needs a symbol (e.g. ! @ #).";
  return null;
}
function send(res: ServerResponse, status: number, obj: unknown): void {
  res.writeHead(status, { "Content-Type": "application/json" });
  res.end(JSON.stringify(obj));
}
async function body(req: IncomingMessage): Promise<any> {
  const chunks: Buffer[] = [];
  for await (const c of req) chunks.push(c as Buffer);
  const text = Buffer.concat(chunks).toString("utf-8");
  if (!text) return {};
  try { return JSON.parse(text); } catch { return { __raw: text }; }
}
function auth(req: IncomingMessage): Account | null {
  const token = (req.headers.authorization || "").replace(/^Bearer\s+/i, "");
  if (!token) return null;
  const row: any = db.prepare("SELECT a.* FROM sessions s JOIN accounts a ON a.id=s.account_id WHERE s.token=?").get(token);
  return row ?? null;
}
function masked(v: string): string {
  if (!v) return "";
  return "••••" + v.slice(-4);
}
function hashSecret(v: string): string {
  return createHash("sha256").update(v).digest("hex");
}
function findingsForScan(scanId: number): any[] {
  const rows: any[] = db.prepare("SELECT * FROM findings WHERE scan_id=? ORDER BY score DESC, id ASC").all(scanId) as any[];
  return rows.map((r) => ({ ...r, breakdown: JSON.parse(r.breakdown) }));
}
function scanSummary(accountId: number): any {
  const scans: any[] = db.prepare("SELECT * FROM scans WHERE account_id=? ORDER BY created_at DESC, id DESC").all(accountId) as any[];
  const all: any[] = [];
  for (const s of scans) all.push(...findingsForScan(s.id));
  const sev: Record<string, number> = { Critical: 0, High: 0, Medium: 0, Low: 0, Info: 0 };
  const status: Record<string, number> = {};
  const hosts = new Map<string, { count: number; max: number }>();
  const services = new Map<string, number>();
  for (const f of all) {
    sev[f.severity] = (sev[f.severity] ?? 0) + 1;
    status[f.status] = (status[f.status] ?? 0) + 1;
    const h = hosts.get(f.host) ?? { count: 0, max: 0 };
    h.count++; h.max = Math.max(h.max, f.score); hosts.set(f.host, h);
    services.set(f.service, (services.get(f.service) ?? 0) + 1);
  }
  const trend = scans.slice().reverse().map((s) => {
    const fs = findingsForScan(s.id);
    return { name: s.name, id: s.id, total: fs.length, critical: fs.filter((f) => f.severity === "Critical").length, avg: fs.length ? Math.round(fs.reduce((a, f) => a + f.score, 0) / fs.length) : 0 };
  });
  return {
    scans: scans.map((s) => ({ id: s.id, name: s.name, created_at: s.created_at, findings: findingsForScan(s.id).length })),
    severity: sev, status, total: all.length,
    riskiestHosts: [...hosts.entries()].map(([host, v]) => ({ host, ...v })).sort((a, b) => b.max - a.max).slice(0, 10),
    commonServices: [...services.entries()].map(([service, count]) => ({ service, count })).sort((a, b) => b.count - a.count).slice(0, 10),
    trend,
    perScan: scans.map((s) => { const fs = findingsForScan(s.id); return { id: s.id, name: s.name, total: fs.length, critical: fs.filter((f) => f.severity === "Critical").length, fixed: fs.filter((f) => f.status === "Fixed").length }; }),
    hostInventory: [...hosts.entries()].map(([host, v]) => ({ host, services: all.filter((f) => f.host === host).map((f) => `${f.service}:${f.port}`).join(", "), maxScore: v.max })),
  };
}
function createScan(accountId: number, name: string, rawFiles: { scanner: string; content: string }[]): number {
  const allRaw: any[] = [];
  for (const f of rawFiles) allRaw.push(...parseScanner(f.scanner, f.content));
  const scored = scoreAll(allRaw);
  const scanId = (db.prepare("INSERT INTO scans (account_id, name, created_at) VALUES (?, ?, ?)").run(accountId, name, new Date().toISOString()) as any).lastInsertRowid as number;
  const ins = db.prepare("INSERT INTO findings (scan_id, host, port, service, title, version, severity, score, breakdown, status, source, scanner) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'Open', ?, ?)");
  for (const f of scored) {
    ins.run(scanId, f.host, f.port, f.service, f.title, f.version || "", f.severity, f.score, JSON.stringify(f.breakdown), f.source, f.scanner);
  }
  return scanId;
}
function fictionalFindings(kind: "before" | "after" | "scanners"): any[] {
  if (kind === "after") {
    return [
      { host: "10.0.5.10", port: 80, service: "http", title: "http", scannerSeverity: "Medium", scanner: "Nmap", source: "nmap" },
      { host: "10.0.5.20", port: 443, service: "https", title: "https", scannerSeverity: "Low", scanner: "Nmap", source: "nmap" },
      { host: "10.0.5.30", port: 22, service: "ssh", title: "ssh", scannerSeverity: "Low", scanner: "Nmap", source: "nmap" },
    ];
  }
  if (kind === "scanners") {
    return [
      { host: "10.0.5.10", port: 23, service: "telnet", title: "telnet", scannerSeverity: "Critical", scanner: "OpenVAS", source: "openvas" },
      { host: "10.0.5.20", port: 6379, service: "redis", title: "redis", scannerSeverity: "Critical", scanner: "Qualys", source: "qualys" },
      { host: "10.0.5.10", port: 80, service: "http", title: "SQL Injection", scannerSeverity: "High", scanner: "OWASP ZAP", source: "zap" },
      { host: "10.0.5.30", port: 443, service: "https", title: "Cross-Site Scripting", scannerSeverity: "High", scanner: "Burp Suite", source: "burp" },
    ];
  }
  // before: 7 findings, fictional only
  return [
    { host: "10.0.5.10", port: 23, service: "telnet", title: "telnet", scannerSeverity: "Critical", scanner: "Nmap", source: "nmap" },
    { host: "10.0.5.10", port: 21, service: "ftp", title: "ftp", scannerSeverity: "High", scanner: "Nmap", source: "nmap" },
    { host: "10.0.5.20", port: 3306, service: "mysql", title: "mysql", scannerSeverity: "High", scanner: "Nmap", source: "nmap" },
    { host: "10.0.5.10", port: 80, service: "http", title: "http", version: "Apache 2.4.49", scannerSeverity: "Medium", scanner: "Nmap", source: "nmap" },
    { host: "10.0.5.20", port: 443, service: "https", title: "https", scannerSeverity: "Low", scanner: "Nmap", source: "nmap" },
    { host: "10.0.5.30", port: 22, service: "ssh", title: "ssh", scannerSeverity: "Low", scanner: "Nmap", source: "nmap" },
    { host: "10.0.5.30", port: 443, service: "https", title: "https", scannerSeverity: "Low", scanner: "Nmap", source: "nmap" },
  ];
}
function createFictionalScan(accountId: number, name: string, kind: "before" | "after" | "scanners"): number {
  const scored = scoreAll(fictionalFindings(kind) as any);
  const scanId = (db.prepare("INSERT INTO scans (account_id, name, created_at) VALUES (?, ?, ?)").run(accountId, name, new Date().toISOString()) as any).lastInsertRowid as number;
  const ins = db.prepare("INSERT INTO findings (scan_id, host, port, service, title, version, severity, score, breakdown, status, source, scanner) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'Open', ?, ?)");
  for (const f of scored) ins.run(scanId, f.host, f.port, f.service, f.title, f.version || "", f.severity, f.score, JSON.stringify(f.breakdown), f.source, f.scanner);
  return scanId;
}
const PORTFOLIO_MD = `# CullSec — Portfolio Pack

## Architecture
CullSec is a local TypeScript fullstack app: a static frontend (HTML/CSS/JavaScript) served by a Node.js TypeScript backend, with a file-backed SQLite database (data/cullsec.db). Sign-in, scans, findings, workflow status, settings hints, and scoring breakdowns are stored in SQLite. No data is sent to external services by this app.

## README (short)
CullSec turns raw scanner output into a prioritised fix list. Upload Nmap, Nessus, OpenVAS, ZAP, Burp, or Qualys output, get one ranked triage with contextual scoring, move findings on a board, compare scans, and export Markdown, CSV, or JSON. Scoring is deterministic and rule-based, not AI. Tickets and alerts are generators until tokens are connected in Settings.

## CV blurb (copy-ready)
Built CullSec, a local vulnerability triage platform: six scanner imports merged into one ranked triage, deterministic contextual scoring with per-finding breakdowns, remediation board and scan comparison, and Markdown/CSV/JSON exports, using TypeScript, Node.js, and SQLite.

## Timed 2-minute demo script
0:00 Sign in and show the dashboard. 0:20 Upload a scan and show the ranked list and a 'Why this score?' breakdown. 0:50 Move a finding on the Board to Fixed. 1:10 Compare before and after scans (7 findings to 3). 1:30 Show a ticket generator preview and an export. 1:50 Close: local, deterministic scoring, no external data sent.
`;
function exportScan(scanId: number, format: string): { type: string; body: string } {
  const scan: any = db.prepare("SELECT * FROM scans WHERE id=?").get(scanId);
  if (!scan) return { type: "text/plain", body: "Scan not found" };
  const fs = findingsForScan(scanId);
  if (format === "csv") {
    const rows = ["host,port,service,title,severity,score,status,scanner", ...fs.map((f) => [f.host, f.port, f.service, `"${String(f.title).replace(/"/g, '""')}"`, f.severity, f.score, f.status, f.scanner].join(","))];
    return { type: "text/csv", body: rows.join("\n") };
  }
  if (format === "json") return { type: "application/json", body: JSON.stringify({ scan, findings: fs }, null, 2) };
  const lines = [`# CullSec Report — ${scan.name}`, "", `Total findings: ${fs.length}`, "", "| Priority | Host | Port | Service | Severity | Score | Status | Why |", "|---|---|---|---|---|---|---|---|"];
  fs.forEach((f, i) => lines.push(`| ${i + 1} | ${f.host} | ${f.port} | ${f.service} | ${f.severity} | ${f.score} | ${f.status} | ${(f.breakdown.reasons || []).join("; ")} |`));
  lines.push("", "## Scoring breakdown (contextual v2 — deterministic, not AI)", "");
  for (const f of fs) lines.push(`- ${f.host}:${f.port} ${f.service} — score ${f.score}: base ${f.breakdown.base} + risky ${f.breakdown.riskyService} + version ${f.breakdown.version} + scanner ${f.breakdown.scannerSeverity} + exposure ${f.breakdown.exposure} + asset ${f.breakdown.assetCriticality} + host ${f.breakdown.hostContext}`);
  lines.push("", "Built by ADYREX — CullSec");
  return { type: "text/markdown", body: lines.join("\n") };
}

const server = createServer(async (req: IncomingMessage, res: ServerResponse) => {
  try {
    const url = new URL(req.url || "/", `http://${req.headers.host || "localhost"}`);
    const path = url.pathname;
    // Static files
    if (req.method === "GET" && !path.startsWith("/api/")) {
      let file = path === "/" ? "/index.html" : path;
      const safe = normalize(join(PUBLIC, file));
      if (!safe.startsWith(PUBLIC) || !existsSync(safe)) { res.writeHead(404); res.end("Not found"); return; }
      const ext = extname(safe);
      const types: Record<string, string> = { ".html": "text/html", ".css": "text/css", ".js": "text/javascript", ".json": "application/json" };
      res.writeHead(200, { "Content-Type": types[ext] || "text/plain" });
      res.end(readFileSync(safe));
      return;
    }
    if (path === "/api/signin" && req.method === "POST") {
      const b = await body(req);
      const email = String(b.email || "").trim().toLowerCase();
      const password = String(b.password || "");
      const name = String(b.name || "").trim();
      if (!email || !password) { send(res, 400, { ok: false, error: "Email and password are required." }); return; }
      const existing: any = db.prepare("SELECT * FROM accounts WHERE email=?").get(email);
      if (!existing) {
        const err = strongPassword(password);
        if (err) { send(res, 400, { ok: false, error: err }); return; }
        if (!name) { send(res, 400, { ok: false, error: "Name is required for a first sign-in." }); return; }
        const salt = randomBytes(16).toString("hex");
        const id = (db.prepare("INSERT INTO accounts (name, email, salt, password_hash, created_at) VALUES (?, ?, ?, ?, ?)").run(name, email, salt, hashPassword(password, salt), new Date().toISOString()) as any).lastInsertRowid;
        const token = randomBytes(32).toString("hex");
        db.prepare("INSERT INTO sessions (token, account_id, created_at) VALUES (?, ?, ?)").run(token, id, new Date().toISOString());
        send(res, 200, { ok: true, token, account: { id, name, email }, isNew: true }); return;
      }
      const calc = hashPassword(password, existing.salt);
      const ok = calc.length === existing.password_hash.length && timingSafeEqual(Buffer.from(calc), Buffer.from(existing.password_hash));
      if (!ok) { send(res, 401, { ok: false, error: "Wrong password. Use the password you entered the first time." }); return; }
      const token = randomBytes(32).toString("hex");
      db.prepare("INSERT INTO sessions (token, account_id, created_at) VALUES (?, ?, ?)").run(token, existing.id, new Date().toISOString());
      send(res, 200, { ok: true, token, account: { id: existing.id, name: existing.name, email: existing.email }, isNew: false }); return;
    }
    const account = auth(req);
    if (!account) { send(res, 401, { ok: false, error: "Sign in required." }); return; }
    if (path === "/api/profile" && req.method === "POST") { const b = await body(req); const name = String(b.name || "").trim(); if (!name) { send(res, 400, { ok: false, error: "Name is required." }); return; } db.prepare("UPDATE accounts SET name=? WHERE id=?").run(name, account.id); send(res, 200, { ok: true, account: { id: account.id, name, email: account.email } }); return; }
    if (path === "/api/dashboard" && req.method === "GET") { send(res, 200, { ok: true, ...scanSummary(account.id) }); return; }
    if (path === "/api/scans" && req.method === "GET") { send(res, 200, { ok: true, scans: scanSummary(account.id).scans }); return; }
    if (path === "/api/scans" && req.method === "POST") {
      const b = await body(req);
      const files = Array.isArray(b.files) ? b.files : [];
      if (!files.length) { send(res, 400, { ok: false, error: "Upload at least one scan file." }); return; }
      const id = createScan(account.id, String(b.name || "Scan"), files);
      send(res, 200, { ok: true, scanId: id, findings: findingsForScan(id) }); return;
    }
    const scanMatch = path.match(/^\/api\/scans\/(\d+)$/);
    if (scanMatch && req.method === "GET") {
      const id = Number(scanMatch[1]);
      const scan: any = db.prepare("SELECT * FROM scans WHERE id=? AND account_id=?").get(id, account.id);
      if (!scan) { send(res, 404, { ok: false, error: "Scan not found." }); return; }
      send(res, 200, { ok: true, scan, findings: findingsForScan(id) }); return;
    }
    if (scanMatch && req.method === "DELETE") {
      db.prepare("DELETE FROM findings WHERE scan_id IN (SELECT id FROM scans WHERE id=? AND account_id=?)").run(Number(scanMatch[1]), account.id);
      db.prepare("DELETE FROM scans WHERE id=? AND account_id=?").run(Number(scanMatch[1]), account.id);
      send(res, 200, { ok: true }); return;
    }
    const findingMatch = path.match(/^\/api\/findings\/(\d+)$/);
    if (findingMatch && req.method === "PATCH") {
      const b = await body(req);
      const allowed = ["Open", "In progress", "Fixed", "Risk accepted", "False positive"];
      if (!allowed.includes(b.status)) { send(res, 400, { ok: false, error: "Invalid status." }); return; }
      db.prepare("UPDATE findings SET status=? WHERE id=? AND scan_id IN (SELECT id FROM scans WHERE account_id=?)").run(b.status, Number(findingMatch[1]), account.id);
      send(res, 200, { ok: true }); return;
    }
    if (path === "/api/compare" && req.method === "GET") {
      const a = findingsForScan(Number(url.searchParams.get("a") || 0));
      const b = findingsForScan(Number(url.searchParams.get("b") || 0));
      const key = (f: any) => `${f.host}:${f.port}:${f.service}`;
      const aKeys = new Set(a.map(key)); const bKeys = new Set(b.map(key));
      send(res, 200, { ok: true, new: b.filter((f) => !aKeys.has(key(f))), resolved: a.filter((f) => !bKeys.has(key(f))), stillOpen: b.filter((f) => aKeys.has(key(f))) }); return;
    }
    if (path.startsWith("/api/demo/") && req.method === "POST") {
      const kind = path.replace("/api/demo/", "") as "before" | "after" | "scanners";
      if (!["before", "after", "scanners"].includes(kind)) { send(res, 400, { ok: false, error: "Unknown demo pack." }); return; }
      const id = createFictionalScan(account.id, `Demo ${kind}`, kind);
      send(res, 200, { ok: true, scanId: id, fictional: true, findings: findingsForScan(id) }); return;
    }
    if (path === "/api/settings" && req.method === "GET") {
      const rows: any[] = db.prepare("SELECT provider, site, project, repo, secret_hint FROM settings WHERE account_id=?").all(account.id) as any[];
      send(res, 200, { ok: true, settings: rows }); return;
    }
    if (path === "/api/settings" && req.method === "POST") {
      const b = await body(req);
      const providers = ["jira", "github", "slack", "teams", "model"];
      for (const p of providers) {
        const v = b[p];
        if (!v) continue;
        const secret = String(v.secret || "");
        db.prepare("INSERT INTO settings (account_id, provider, site, project, repo, secret_hint, secret_hash) VALUES (?, ?, ?, ?, ?, ?, ?) ON CONFLICT(account_id, provider) DO UPDATE SET site=excluded.site, project=excluded.project, repo=excluded.repo, secret_hint=excluded.secret_hint, secret_hash=excluded.secret_hash")
          .run(account.id, p, String(v.site || ""), String(v.project || ""), String(v.repo || ""), secret ? masked(secret) : "", secret ? hashSecret(secret) : "");
      }
      send(res, 200, { ok: true, note: "Secrets are hashed server-side; only a masked last-4 hint is returned. Nothing is sent anywhere." }); return;
    }
    const exportMatch = path.match(/^\/api\/export\/(\d+)$/);
    if (exportMatch && req.method === "GET") {
      const format = url.searchParams.get("format") || "md";
      const out = exportScan(Number(exportMatch[1]), format);
      res.writeHead(200, { "Content-Type": out.type, "Content-Disposition": `attachment; filename="report.${format === "md" ? "md" : format}"` });
      res.end(out.body); return;
    }
    if (path === "/api/portfolio" && req.method === "GET") {
      res.writeHead(200, { "Content-Type": "text/markdown", "Content-Disposition": 'attachment; filename="portfolio-pack.md"' });
      res.end(PORTFOLIO_MD); return;
    }
    send(res, 404, { ok: false, error: "Not found." });
  } catch (e: any) {
    send(res, 500, { ok: false, error: String(e?.message || e) });
  }
});
server.listen(PORT, () => console.log(`CullSec running on http://localhost:${PORT}`));
