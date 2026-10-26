# CullSec — Vulnerability Triage & Management

**CullSec turns raw scanner output into a prioritised fix list.**

It is a local, private triage platform: upload scans from Nmap, Nessus, OpenVAS/GVM, OWASP ZAP, Burp Suite, or Qualys, and CullSec scores, deduplicates, ranks, and tracks every finding until it is fixed — then exports the proof as Markdown, CSV, or JSON.

> **CullSec is not a scanner.** It reads scanner output. It is not AI, and it has no live integrations. Scoring is deterministic and rule-based, and every score shows its full breakdown.

Built by ADYREX.

## Screenshots

### Overview — your risk, at a glance

![Overview dashboard](docs/screenshots/overview.png)

### Overview — Common services, aligned by exposure

![Common services](docs/screenshots/common-services.png)

### Reviewer walkthrough — 2 minutes, fictional data only

![Walkthrough](docs/screenshots/walkthrough.png)

## Features

| Area | What it does |
|---|---|
| **Saved accounts** | First sign-in creates the account; the same email and password reopens it. Strong-password rule for new accounts (8+ characters, lowercase, uppercase, number, symbol). Passwords are hashed server-side with scrypt and a per-account salt. |
| **Scanner imports** | Nmap XML, Nessus CSV, OpenVAS/GVM XML, OWASP ZAP JSON/XML, Burp Suite XML, Qualys CSV/XML — merged into one ranked triage, with cross-scanner dedupe by host, port, and service. |
| **Contextual scoring v2** | Deterministic 0–100 score per finding, with the full breakdown stored and shown under "Why this score?" — under the finding itself and in the Score breakdown panel. |
| **Dashboard** | Severity mix, remediation progress, threat level (HIGH / ELEVATED / LOW from real counts), riskiest hosts, common services, host inventory, per-scan summary, and scan trend. |
| **Findings explorer** | Search, severity filter, status filter, and sort by score or host. |
| **Remediation board** | Open → In progress → Fixed, plus Risk accepted and False positive. Status is saved in the database. |
| **Scan comparison** | Compare two scans: new, resolved, and still open findings. |
| **Exports** | Markdown, CSV, and JSON reports, ending with "Built by ADYREX". |
| **Demo data** | Fictional, clearly labelled demo packs: before (7 findings) → after (3 findings), plus a sample scan and a new-scanners pack. Hosts are fictional lab hosts (`10.0.5.x`). |
| **Themes** | Light and Dark, chosen on the start page and saved on your device. |

## Quick start

**Requirements:** Node.js 24 (tested with Node v24.22.1). No separate database server is needed — CullSec uses Node's built-in SQLite (`node:sqlite`).

```bash
git clone https://github.com/adityawakde/cullsec_.git
cd cullsec_
npm install
npm run dev
```

Then open <http://localhost:3000>.

The database file is created at `data/cullsec.db` on first run. To reset local test data, stop the server and delete `data/cullsec.db`.

## How to use it

### 1. Sign in

Enter a name (first time only), email, and a strong password. The first sign-in saves your account; the same email and password brings it back. A wrong password is rejected.

Optional: tick **"Save my login info on this device"** to have your email and password prefilled next time you open CullSec in that browser. See the warning in [SECURITY.md](SECURITY.md) — do not tick this on a shared computer.

### 2. Choose your scanners, then triage

In **Triage**:

1. Tick the scanners you want to use — one, or several.
2. Only the upload boxes for those scanners appear.
3. Upload the scan files, give the scan a name, and tap **Run triage →**.

Or, to try it without a scan file, tap **Load reviewer demo (fictional)** or **Load my sample scan**.

### 3. Work the board, prove the fix

- **Overview** shows your dashboard and threat level.
- **Board** moves findings through Open → In progress → Fixed.
- **Compare** diffs two scans (for example, before and after fixes).
- **Exports** downloads the report as Markdown, CSV, or JSON.

## Scanner support

| Scanner | Format | How to get it |
|---|---|---|
| Nmap | XML | `nmap -sV -oX scan.xml <target>` |
| Nessus | CSV | Export → CSV |
| OpenVAS / GVM | XML | GVM report download, XML format |
| OWASP ZAP | JSON / XML | Report → Generate report |
| Burp Suite | XML | Issues → Save / export XML |
| Qualys | CSV / XML | Qualys report, CSV or XML format |

You can also paste Nmap XML directly in Triage ("Paste XML instead"). Pasted text must include open ports (`state="open"`) to parse into findings.

## How scoring works — contextual scoring v2

Score = base + risky service + known-bad version + scanner severity + exposure + asset criticality + host context, capped at 100. Deterministic — the same finding always scores the same way.

| Factor | Points |
|---|---|
| Base | 10 |
| Risky service by port | Telnet (23) 70 · Redis (6379) / MongoDB (27017) 60 · SMB (445) / MSSQL (1433) / MySQL (3306) / PostgreSQL (5432) / VNC (5900) 50 · FTP (21) 40 |
| Known-bad version | +25 when a version hint matches (for example, Apache `2.4.49`, vsftpd `2.3.4`) |
| Scanner severity | Critical 30 · High 20 · Medium 10 · Low 5 · Info 0 |
| Exposure | +5 for cleartext protocols (Telnet, FTP) |
| Asset criticality | +5 for database / cache ports |
| Host context | +3 when a host has 3 or more findings |
| **Total** | **Capped at 100** |

Severity bands from score: Critical 85–100 · High 65–84 · Medium 40–64 · Low 15–39 · Info 0–14.

## Project structure

```
cullsec_/
├── public/
│   ├── index.html    # Start page, sign-in, walkthrough, Platform, and signed-in tabs
│   ├── styles.css    # Light / Dark themes, dashboard, board, and findings styles
│   └── app.js        # Frontend: sign-in, triage, board, compare, exports
├── src/
│   ├── server.ts     # Node.js + TypeScript backend, API, exports
│   ├── db.ts         # SQLite schema (accounts, scans, findings)
│   ├── parsers.ts    # Six scanner parsers + dedupe
│   └── scoring.ts    # Contextual scoring v2 (deterministic, not AI)
├── docs/
│   └── screenshots/  # Screenshots used in this README
├── package.json
├── tsconfig.json
└── README.md
```

## Development

```bash
npm run build   # TypeScript only
npm start       # Run the built server (after build)
npm run dev     # Build + run
```

## Security and privacy

- Passwords are hashed server-side (scrypt + per-account salt), never stored in plain text in the database.
- All data lives in one local SQLite file (`data/cullsec.db`). **Nothing is sent anywhere by this app** — no external API calls, no live integrations, no telemetry.
- Only scan networks you own or have explicit permission to test.
- See [SECURITY.md](SECURITY.md) for the full policy, including the saved-login warning.

## Limitations — stated plainly

- **Local only.** CullSec runs on your machine at `http://localhost:3000`. There is no hosted public demo, and it is not designed to be deployed as-is to serverless hosting (which has no persistent disk for the SQLite file) — a persistent host is needed for that.
- **No AI.** Scoring is rule-based. No model is connected, and no scan data is sent to any model.
- **No live integrations.** There is no live Jira, GitHub, Slack, or Teams posting.
- **No automated test suite yet.** Verification is manual, against the running app.

## Contributing

Issues and pull requests are welcome. Please keep contributions local-first, deterministic, and honest about what is and is not connected — no new feature should claim a live service or AI capability it does not have. Use fictional demo data (`10.0.5.x`) in examples and screenshots, never real scan data.

## License

MIT — see [LICENSE](LICENSE).

---

CullSec · Built by ADYREX
