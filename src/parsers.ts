import { bandFromScore, normalizeSeverity, scoreFinding } from "./scoring.js";

export type RawFinding = {
  host: string; port: number; service: string; title: string; version?: string;
  scannerSeverity?: string; cleartext?: boolean; scanner: string; source: string;
};
export type ScoredFinding = RawFinding & { score: number; severity: string; breakdown: ReturnType<typeof scoreFinding> };

function esc(s: string): string { return s.replace(/&/g, "&amp;"); }
function block(content: string, tag: string): string[] {
  const out: string[] = []; const re = new RegExp(`<${tag}[^>]*>([\\s\\S]*?)</${tag}>`, "gi"); let m;
  while ((m = re.exec(content)) !== null) out.push(m[1]);
  return out;
}
function tag(content: string, name: string): string {
  const m = content.match(new RegExp(`<${name}[^>]*>([\\s\\S]*?)</${name}>`, "i"));
  return m ? m[1].trim() : "";
}
function attr(content: string, name: string): string {
  const m = content.match(new RegExp(`${name}\\s*=\\s*"([^"]*)"`, "i"));
  return m ? m[1] : "";
}
function parseCsv(text: string): Record<string, string>[] {
  const lines = text.split(/\r?\n/).filter((l) => l.trim().length > 0);
  if (lines.length < 2) return [];
  const split = (line: string): string[] => {
    const out: string[] = []; let cur = ""; let q = false;
    for (let i = 0; i < line.length; i++) {
      const c = line[i];
      if (c === '"') { if (q && line[i + 1] === '"') { cur += '"'; i++; } else q = !q; }
      else if (c === "," && !q) { out.push(cur); cur = ""; }
      else cur += c;
    }
    out.push(cur); return out.map((s) => s.trim());
  };
  const headers = split(lines[0]).map((h) => h.toLowerCase());
  return lines.slice(1).map((line) => {
    const vals = split(line); const row: Record<string, string> = {};
    headers.forEach((h, i) => { row[h] = vals[i] ?? ""; }); return row;
  });
}

export function parseNmap(text: string): RawFinding[] {
  const out: RawFinding[] = [];
  const hostRe = /<host[^>]*>([\s\S]*?)<\/host>/gi; let hm;
  while ((hm = hostRe.exec(text)) !== null) {
    const hostBlock = hm[1];
    const addrMatch = hostBlock.match(/<address[^>]*addr="([^"]*)"/i);
    const addr = addrMatch ? addrMatch[1] : "unknown";
    const portRe = /<port\s([^>]*)>([\s\S]*?)<\/port>/gi; let pm;
    while ((pm = portRe.exec(hostBlock)) !== null) {
      const portAttrs = pm[1]; const portBlock = pm[2];
      if (!/state="open"/i.test(portBlock)) continue;
      const portId = portAttrs.match(/portid="([^"]*)"/i)?.[1] || "0";
      const port = parseInt(portId, 10);
      const svcMatch = portBlock.match(/<service([^>]*)>/i);
      const svcAttrs = svcMatch ? svcMatch[1] : "";
      const service = (svcAttrs.match(/name="([^"]*)"/i)?.[1]) || "";
      const product = (svcAttrs.match(/product="([^"]*)"/i)?.[1]) || "";
      const version = (svcAttrs.match(/version="([^"]*)"/i)?.[1]) || "";
      const ver = [product, version].filter(Boolean).join(" ").trim();
      out.push({ host: addr, port, service, title: service || `Port ${port}`, version: ver, scanner: "Nmap", source: "nmap", cleartext: service === "ftp" || service === "telnet" });
    }
  }
  return out;
}
export function parseNessus(text: string): RawFinding[] {
  return parseCsv(text).filter((r) => r.host && r.port).map((r) => ({
    host: r.host, port: parseInt(r.port, 10) || 0, service: r.name || "nessus",
    title: r.name || "Nessus finding", scannerSeverity: normalizeSeverity(r.severity || ""),
    scanner: "Nessus", source: "nessus",
  }));
}
export function parseOpenvas(text: string): RawFinding[] {
  const out: RawFinding[] = [];
  for (const b of block(text, "result")) {
    const host = tag(b, "host") || "unknown";
    const portRaw = tag(b, "port") || "0";
    const port = parseInt(portRaw.replace(/[^0-9]/g, "") || "0", 10);
    const name = tag(b, "name") || "OpenVAS finding";
    const sevRaw = tag(b, "severity") || "";
    out.push({ host, port, service: name, title: name, scannerSeverity: normalizeSeverity(sevRaw), scanner: "OpenVAS", source: "openvas" });
  }
  return out;
}
export function parseZap(text: string): RawFinding[] {
  const out: RawFinding[] = [];
  const trimmed = text.trim();
  if (trimmed.startsWith("{") || trimmed.startsWith("[")) {
    try {
      const data: any = JSON.parse(trimmed);
      const sites: any[] = Array.isArray(data) ? data : (data.site || (data.alerts ? [{ alerts: data.alerts }] : []));
      for (const site of sites) {
        const host = String(site.name || site.url || "unknown").replace(/^https?:\/\//, "").split("/")[0].split(":")[0] || "unknown";
        for (const a of site.alerts || []) {
          out.push({ host, port: 80, service: a.name || "ZAP alert", title: a.name || "ZAP alert", scannerSeverity: normalizeSeverity(a.riskdesc || a.risk || ""), scanner: "OWASP ZAP", source: "zap" });
        }
      }
      return out;
    } catch { /* fall through to XML */ }
  }
  for (const b of block(text, "alertitem")) {
    const host = (tag(b, "host") || "unknown").replace(/^https?:\/\//, "").split("/")[0];
    out.push({ host, port: 80, service: tag(b, "name") || "ZAP alert", title: tag(b, "name") || "ZAP alert", scannerSeverity: normalizeSeverity(tag(b, "riskdesc")), scanner: "OWASP ZAP", source: "zap" });
  }
  return out;
}
export function parseBurp(text: string): RawFinding[] {
  const out: RawFinding[] = [];
  for (const b of block(text, "issue")) {
    const host = tag(b, "ip") || "unknown";
    const rest = b.replace(/<host>[\s\S]*?<\/host>/i, "");
    const port = parseInt(tag(rest, "port") || "0", 10);
    const name = tag(rest, "name") || "Burp finding";
    out.push({ host, port, service: name, title: name, scannerSeverity: normalizeSeverity(tag(rest, "severity")), scanner: "Burp Suite", source: "burp" });
  }
  return out;
}
export function parseQualys(text: string): RawFinding[] {
  if (text.trim().startsWith("<")) {
    const out: RawFinding[] = [];
    for (const hb of block(text, "HOST")) {
      const host = tag(hb, "IP") || "unknown";
      for (const vb of block(hb, "VULN")) {
        const port = parseInt((tag(vb, "PORT") || "0").replace(/[^0-9]/g, "") || "0", 10);
        const title = tag(vb, "TITLE") || "Qualys finding";
        out.push({ host, port, service: title, title, scannerSeverity: normalizeSeverity(tag(vb, "SEVERITY")), scanner: "Qualys", source: "qualys" });
      }
    }
    return out;
  }
  return parseCsv(text).filter((r) => r.host).map((r) => ({
    host: r.host, port: parseInt((r.port || "0").replace(/[^0-9]/g, "") || "0", 10),
    service: r.title || r.name || "Qualys finding", title: r.title || r.name || "Qualys finding",
    scannerSeverity: normalizeSeverity(r.severity || ""), scanner: "Qualys", source: "qualys",
  }));
}
export function parseScanner(scanner: string, text: string): RawFinding[] {
  const s = scanner.toLowerCase();
  if (s.includes("nmap")) return parseNmap(text);
  if (s.includes("nessus")) return parseNessus(text);
  if (s.includes("openvas") || s.includes("gvm")) return parseOpenvas(text);
  if (s.includes("zap")) return parseZap(text);
  if (s.includes("burp")) return parseBurp(text);
  if (s.includes("qualys")) return parseQualys(text);
  return [];
}
export function scoreAll(raw: RawFinding[]): ScoredFinding[] {
  const hostCounts = new Map<string, number>();
  for (const f of raw) hostCounts.set(f.host, (hostCounts.get(f.host) ?? 0) + 1);
  const rank: Record<string, number> = { Info: 0, Low: 1, Medium: 2, High: 3, Critical: 4 };
  const scored = raw.map((f) => {
    const breakdown = scoreFinding({ port: f.port, service: f.service, version: f.version, scannerSeverity: f.scannerSeverity, cleartext: f.cleartext, hostFindingCount: hostCounts.get(f.host) ?? 0 });
    const band = bandFromScore(breakdown.total);
    const severity = f.scannerSeverity && f.scanner !== "Nmap" && (rank[f.scannerSeverity] ?? 0) > (rank[band] ?? 0) ? f.scannerSeverity : band;
    return { ...f, score: breakdown.total, severity, breakdown };
  });
  // Dedupe by host:port:service/title, keep highest score, merge scanners
  const map = new Map<string, ScoredFinding>();
  for (const f of scored) {
    const key = `${f.host}:${f.port}:${(f.service || f.title).toLowerCase()}`;
    const existing = map.get(key);
    if (!existing || f.score > existing.score) {
      map.set(key, { ...f, scanner: existing ? `${existing.scanner}, ${f.scanner}` : f.scanner });
    } else if (existing && !existing.scanner.includes(f.scanner)) {
      existing.scanner = `${existing.scanner}, ${f.scanner}`;
    }
  }
  return [...map.values()].sort((a, b) => b.score - a.score);
}
export function escapeHtml(s: string): string { return esc(String(s)).replace(/</g, "&lt;").replace(/>/g, "&gt;"); }
