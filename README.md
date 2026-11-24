# Vault Health

Credential hygiene and offboarding planner for small teams. For the IT admin or office manager at a 10–200 person company who has a shared-password mess and someone leaving on Friday.

Live: https://vault-health-theta.vercel.app

## The pain

Shared logins pile up in password managers, and nobody can say which ones a departing employee could see. The usual advice ("rotate shared passwords when people leave") is hard to act on without a list. Insurers increasingly want proof that it happened.

## What it does

- **Import** CSV exports from 1Password (CSV or .1pux), Bitwarden, LastPass, Chrome/Edge, Firefox, Apple Passwords or any CSV. Format detection, column mapping and a validation report with line numbers.
- Importers are tested against the layouts of the public sample exports in Bitwarden's importer test suite (Chrome incl. Android app logins, Firefox, Safari old and new, 1Password 7 Mac/Windows CSV, 1Password 8 CSV, 1PUX incl. server, database, router, email and API credential items).
- **Analyze** strength (zxcvbn), exact reuse and near-reuse (`Summer2024!` vs `Summer2025!`), breached passwords (Have I Been Pwned, k-anonymity with padding), old passwords, sites with 2FA support but no TOTP saved (2fa.directory), and shared-vault exposure. Per-item risk with published weights and an overall health score.
- **Offboard**: pick the person leaving (from a vault access list, or tag items by hand) to get a rotation checklist ordered by blast radius, with owners, the items sharing each password and SSO candidates. Progress is tracked across sessions.
- **Act**: prioritized fix plan CSV, printable report for leadership or an insurer, policy attestation, and a strong password generator (`crypto.getRandomValues`, never stored).
- **History**: a snapshot per import, a health trend and a compare view (items fixed, items worse).
- Workspaces in IndexedDB, optional sign-in to sync across devices (Supabase), light and dark themes, three synthetic sample vaults.

## Known gaps

- Bitwarden, LastPass, Chrome and Apple exports carry no password-changed date, so age checks only run for Firefox, 1PUX, 1Password 7 Mac CSV and generic CSVs with a date column.
- Encrypted exports (Bitwarden encrypted JSON, 1Password 1PIF) are not read.
- The SSO candidate list is a hand-kept list of common business apps, not a live dataset.

## Security model

The export is parsed in the browser. Passwords and usernames are never written to IndexedDB, localStorage or the cloud. Only derived findings are kept (title, domain, vault, strength, reuse group id from a salted hash whose salt is discarded, breached yes/no, last-changed date, 2FA availability). A strict CSP limits network access to HIBP, 2fa.directory and the sync server. See `/security` in the app.

## Run locally

```
npm install
npm run dev
npm test     # engine tests
npm run build
```

Copy `.env.example` to `.env` and fill in the Supabase URL and publishable key to enable sync. Everything else works without it.

## Tests and CI

```
npm test                      # engine unit tests (node:test)
npx playwright install chromium   # once
npm run test:e2e              # builds, then runs the browser tests against `vite preview`
E2E_PORT=4800 npm run test:e2e    # use another port (default 4173)
```

The Playwright (Chromium) suite in `e2e/` drives the production build signed out. Every credential in it is made up. Network access is closed: the page can only reach the preview server, the Have I Been Pwned and 2fa.directory calls are answered by stubs, and every other host (fonts, Supabase) is blocked, so no test can reach a real service. Each test also fails on an uncaught page error or a request to an unexpected host. It covers the sample vaults, CSV and 1PUX imports, what is stored, downloaded and sent after an import (no password or username anywhere), failed breach lookups, offboarding, persistence across reloads, and encrypted, empty and truncated exports. `e2e/known-bugs.spec.ts` holds tests for filed bugs, marked `test.fail()` until they are fixed.

GitHub Actions (`.github/workflows/ci.yml`, job `test`) runs install, build, unit tests and the E2E suite on every pull request and on pushes to `main`. `vercel.json` turns Git deployments off for every branch except `main`, so pull requests do not create Vercel previews; CI is the gate.
