# Vault Health

Credential hygiene and offboarding planner for small teams. For the IT admin or office manager at a 10–200 person company who has a shared-password mess and someone leaving on Friday.

Live: https://vault-health.vercel.app

## The pain

Shared logins pile up in password managers, and nobody can say which ones a departing employee could see. The usual advice ("rotate shared passwords when people leave") is hard to act on without a list. Insurers increasingly want proof that it happened.

## What it does

- **Import** CSV exports from 1Password (CSV or .1pux), Bitwarden, LastPass, Chrome/Edge, Firefox, Apple Passwords or any CSV. Format detection, column mapping and a validation report with line numbers.
- **Analyze** strength (zxcvbn), exact reuse and near-reuse (`Summer2024!` vs `Summer2025!`), breached passwords (Have I Been Pwned, k-anonymity with padding), old passwords, sites with 2FA support but no TOTP saved (2fa.directory), and shared-vault exposure. Per-item risk with published weights and an overall health score.
- **Offboard**: pick the person leaving (from a vault access list, or tag items by hand) to get a rotation checklist ordered by blast radius, with owners, the items sharing each password and SSO candidates. Progress is tracked across sessions.
- **Act**: prioritized fix plan CSV, printable report for leadership or an insurer, policy attestation, and a strong password generator (`crypto.getRandomValues`, never stored).
- **History**: a snapshot per import, a health trend and a compare view (items fixed, items worse).
- Workspaces in IndexedDB, optional sign-in to sync across devices (Supabase), light and dark themes, three synthetic sample vaults.

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
