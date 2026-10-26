# CullSec

CullSec is a local vulnerability triage platform. It turns raw scanner output into a prioritised fix list.

CullSec is not a scanner. It reads scan output, deduplicates findings, scores them with deterministic contextual scoring, and writes a report in fix order.

## What it does

- Saved accounts with sign-in. First sign-in creates the account; the same email and password reopens it. Strong password rule for new accounts: 8+ characters with lowercase, uppercase, number, and symbol. Passwords are hashed server-side.
- Six scanner imports, server-side: Nmap XML, Nessus CSV, OpenVAS/GVM XML, OWASP ZAP JSON/XML, Burp Suite XML, Qualys CSV/XML, merged into one ranked triage with cross-scanner dedupe.
- Server-side contextual scoring v2, deterministic, NOT AI: service base + known-bad version + scanner severity + exposure + asset criticality + host context, capped at 100, with the full breakdown stored per finding and shown under "Why this score?".
- Dashboard, findings explorer, remediation board (Open / In progress / Fixed / Risk accepted / False positive), scan-to-scan Compare, host inventory, and per-scan summaries.
- Reports and exports: Markdown, CSV and JSON reports. Nothing is sent anywhere by this app.
- Exports in Markdown, CSV, and JSON.
- Fictional demo packs, clearly labelled fictional, including a before/after pack (7 findings to 3) and a new-scanners demo pack.
- Platform sections in a top line.

## Requirements

- Node.js 24 (tested with Node v24.22.1). Node's built-in SQLite (`node:sqlite`) is used, so no separate database server is needed.
- No other runtime dependencies. TypeScript is a dev dependency for the build.

## How to run

```bash
npm install
npm run dev
```

Then open http://localhost:3000

The database file is created at `data/cullsec.db` on first run. To reset local test data, stop the server and delete `data/cullsec.db`.

## How to sign in

1. Open http://localhost:3000.
2. On the first page, scroll through the story chapters or use "Skip to sign in".
3. Enter a name (first time only), email, and a strong password.
4. The same email and password sign you back into the same account. A wrong password is rejected.

## How to upload scans

1. Sign in.
2. Go to Triage.
3. Upload one or more scan files, enter a scan name, and choose "Run triage".
4. Use Overview for the dashboard, Board to change finding status, Compare to compare two scans, and Exports to download a report.

## Safety note

Only scan networks you own or have explicit permission to test.
