# Security Policy

## What CullSec is — and is not

CullSec is a **local, private** vulnerability triage tool. It is not a scanner,
not a hosted service, and not a production security product. It reads scanner
output you provide, ranks it, and stores it in a local SQLite file on the
machine where it runs.

## Reporting a vulnerability

If you find a security issue in this repository, please do not open a public
issue with exploit details. Instead, open an issue with a high-level
description, or contact the maintainer through the repository, and allow
reasonable time for a fix before public disclosure.

## Safe use

- **Only scan networks you own or have explicit permission to test.**
  CullSec does not scan anything itself, but the scan files you upload
  should only come from authorised testing.
- **Do not use real credentials, real customer data, or real production
  scans in demo data or screenshots.** The included demo data is fictional
  lab data (hosts `10.0.5.x`) for this reason.
- **Saved login warning:** if you tick "Save my login info on this device",
  your email and password are stored in that browser's local storage so
  they can be prefilled next time. Do not tick this on a shared computer.
  For stronger protection, use your browser's or operating system's
  password manager instead.
- **Passwords are hashed server-side** with scrypt and a per-account salt
  and are never stored in plain text in the database. Saved-login data in
  the browser is a separate, weaker convenience feature — see above.
- **No data is sent anywhere by this app.** There are no external API
  calls, no live integrations, and no telemetry.

## Scope of this policy

This policy covers the code in this repository only. It does not cover
any network you choose to scan, or any third-party scanner whose output
you import.
