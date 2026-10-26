export type Breakdown = {
  base: number;
  riskyService: number;
  version: number;
  scannerSeverity: number;
  exposure: number;
  assetCriticality: number;
  hostContext: number;
  total: number;
  reasons: string[];
};

const RISKY: Record<number, { label: string; points: number }> = {
  21: { label: "FTP, often cleartext", points: 40 },
  23: { label: "Telnet, cleartext login", points: 70 },
  445: { label: "SMB, common lateral-movement target", points: 50 },
  1433: { label: "MSSQL exposed", points: 50 },
  3306: { label: "MySQL exposed", points: 50 },
  5432: { label: "PostgreSQL exposed", points: 50 },
  6379: { label: "Redis, often unauthenticated if exposed", points: 60 },
  27017: { label: "MongoDB exposed", points: 60 },
  5900: { label: "VNC, remote desktop", points: 50 },
};
const DB_PORTS = new Set([1433, 3306, 5432, 6379, 27017]);
const OLD_HINTS = ["2.4.49", "vsftpd 2.3.4", "2.2.", "1.0"];
export const SEVERITY_POINTS: Record<string, number> = {
  Critical: 30, High: 20, Medium: 10, Low: 5, Info: 0,
};
export function normalizeSeverity(s: string): string {
  const raw = (s || "").trim();
  const num = Number(raw);
  if (!Number.isNaN(num) && raw !== "") {
    if (num >= 9) return "Critical";
    if (num >= 7) return "High";
    if (num >= 4) return "Medium";
    if (num > 0) return "Low";
    return "Info";
  }
  const t = raw.toLowerCase();
  if (t.includes("critical") || t === "5" || t === "5.0") return "Critical";
  if (t.includes("high") || t === "4") return "High";
  if (t.includes("medium") || t === "3") return "Medium";
  if (t.includes("low") || t === "2") return "Low";
  return "Info";
}
export function bandFromScore(score: number): string {
  if (score >= 85) return "Critical";
  if (score >= 65) return "High";
  if (score >= 40) return "Medium";
  if (score >= 15) return "Low";
  return "Info";
}
export function scoreFinding(input: {
  port: number; service: string; version?: string;
  scannerSeverity?: string; cleartext?: boolean; hostFindingCount?: number;
}): Breakdown {
  const reasons: string[] = [];
  const base = 10;
  let riskyService = 0;
  const r = RISKY[input.port];
  if (r) { riskyService = r.points; reasons.push(r.label); }
  let version = 0;
  if (input.version) {
    for (const h of OLD_HINTS) {
      if (input.version.includes(h)) { version = 25; reasons.push(`Old version hint: ${input.version}`); break; }
    }
  }
  const scannerSeverity = input.scannerSeverity ? (SEVERITY_POINTS[input.scannerSeverity] ?? 0) : 0;
  if (input.scannerSeverity) reasons.push(`Scanner severity: ${input.scannerSeverity}`);
  const exposure = input.cleartext || input.service === "ftp" || input.service === "telnet" ? 5 : 0;
  if (exposure) reasons.push("Cleartext protocol");
  const assetCriticality = DB_PORTS.has(input.port) ? 5 : 0;
  if (assetCriticality) reasons.push("Database/cache service exposed");
  const hostContext = (input.hostFindingCount ?? 0) >= 3 ? 3 : 0;
  if (hostContext) reasons.push("Host has multiple open services");
  const total = Math.min(100, base + riskyService + version + scannerSeverity + exposure + assetCriticality + hostContext);
  return { base, riskyService, version, scannerSeverity, exposure, assetCriticality, hostContext, total, reasons };
}
