import { WEIGHTS } from './engine/risk.ts'
import { Code, Link } from './ui.tsx'

const MANAGERS: { id: string; name: string; file: string; steps: string[]; notes: string[] }[] = [
  {
    id: '1password', name: '1Password', file: '.1pux (recommended) or .csv',
    steps: ['Open the 1Password desktop app (export is not available on 1Password.com or mobile).', 'Choose File › Export, then pick the account.', 'Enter your account password.', 'Choose 1PUX to keep vault names, or CSV. Then Export Data.'],
    notes: ['1PUX keeps vault names and vault type, which is how shared vaults are detected. 1Password CSV has no vault column, so everything lands in one vault.', '1PUX has no “password changed” field. Age comes from the newest password-history entry, or the date the item was created when the password was never changed. Editing a tag or note does not reset it.', 'Server, Database, Wireless Router, Email Account and API Credential items are included: each password field in them (console, SMTP, base station, Wi-Fi, credential) becomes its own row. PINs, card numbers and ID numbers are left out.', '1Password CSV skips archived items, like 1PUX. 1Password 7 CSV exports (Mac “all fields” and Windows) are recognized too; on Mac the Modified Date column is used as the age.', 'In 1Password Business, an owner can restrict export. If the menu item is missing, ask an owner.', 'A 1PUX is a zip. It is unpacked in your browser.'],
  },
  {
    id: 'bitwarden', name: 'Bitwarden', file: '.csv',
    steps: ['Personal vault: web vault › Tools › Export vault, format .csv, enter your master password.', 'Organization vault: Admin Console › your organization › Export vault, format .csv.'],
    notes: ['Organization exports include a collections column; items in a collection are treated as shared.', 'The CSV includes login_totp, so “2FA not set” is accurate.', 'Bitwarden CSV has no password-changed date, so age is skipped. Encrypted JSON exports are not supported.', 'Items with several URIs list them comma-separated in login_uri; the first one names the site.'],
  },
  {
    id: 'lastpass', name: 'LastPass', file: '.csv',
    steps: ['In the browser extension: Account › Fix a problem yourself › Advanced options › Export items › LastPass CSV file.', 'Or in the web vault: Advanced options › Export. Re-enter your master password and confirm the email if asked.'],
    notes: ['The grouping column is the folder. Shared folders start with “Shared-” and are treated as shared.', 'No password-changed date in the CSV.', 'If the CSV opens in a browser tab instead of downloading, save the page as a .csv file.'],
  },
  {
    id: 'chrome', name: 'Chrome and Edge', file: '.csv',
    steps: ['Chrome: open chrome://password-manager/settings › Export passwords › Download file.', 'Edge: open edge://wallet/passwords (or Settings › Passwords) › ⋯ › Export passwords.'],
    notes: ['Browser exports have no vault, TOTP or date columns. Everything is one “Browser” vault, age is skipped and 2FA can only be flagged as available.', 'Android app logins (android://…@com.example.app) are named after the app package and matched to its domain (com.example → example.com).'],
  },
  {
    id: 'firefox', name: 'Firefox', file: '.csv',
    steps: ['Open about:logins.', 'Click ⋯ (top right) › Export passwords, confirm, and save.'],
    notes: ['Firefox is the only browser that exports timePasswordChanged, so age checks work.', 'The chrome://FirefoxAccounts row holds Firefox Sync keys, not a site password, and is skipped.'],
  },
  {
    id: 'apple', name: 'Apple Passwords', file: '.csv',
    steps: ['macOS 15 or later: open the Passwords app › File › Export All Passwords to File.', 'macOS 14: Safari › Settings › Passwords, then File › Export › Passwords. Older Safari exports with only Title, Url, Username and Password columns also work.'],
    notes: ['The OTPAuth column marks items with a saved verification code.', 'No vault or date columns. Shared groups are not included in the export.'],
  },
]

export default function Docs() {
  return (
    <section className="page narrow docs">
      <div className="eyebrow">Docs</div>
      <h1>Getting your data in</h1>
      <p className="lede">Vault Health reads the export file your password manager already makes. The file is read in your browser and never uploaded. Delete the export from your Downloads folder when you are done: it is plain text.</p>
      <p className="note">Steps last reviewed November 2026 against the current desktop apps. Menus move between releases; if a label differs, look for “Export” in the app’s settings.</p>
      <nav className="toc" aria-label="On this page">
        {MANAGERS.map(m => <a key={m.id} href={`#${m.id}`}>{m.name}</a>)}
        <a href="#generic">Other CSV</a><a href="#access">Access list</a><a href="#scoring">Scoring</a><a href="#checks">Checks</a>
      </nav>

      {MANAGERS.map(m => (
        <article key={m.id} id={m.id} className="doc-section">
          <h2>{m.name} <span className="muted small">{m.file}</span></h2>
          <ol>{m.steps.map(s => <li key={s}>{s}</li>)}</ol>
          <ul className="notes">{m.notes.map(n => <li key={n}>{n}</li>)}</ul>
        </article>
      ))}

      <article id="generic" className="doc-section">
        <h2>Any other CSV</h2>
        <p>Anything with a header row and a password column works. Recognized column names (case-insensitive):</p>
        <ul className="notes">
          <li><b>title</b>: title, name, item, account</li>
          <li><b>url</b>: url, login_uri, website, uri</li>
          <li><b>password</b>: password, login_password, pass</li>
          <li><b>totp</b>: otpauth, totp, login_totp, otp (any non-empty value means a TOTP is saved)</li>
          <li><b>vault</b>: vault, collections, folder, grouping, group</li>
          <li><b>last changed</b>: last_changed, password_changed, modified, updated (ISO dates or epoch seconds/milliseconds)</li>
        </ul>
        <Code label="CSV" code={'vault,title,url,username,password,totp,last_changed\nMarketing,Instagram,https://instagram.com,social@acme.example,•••,,2023-04-01'} />
      </article>

      <article id="access" className="doc-section">
        <h2>Access list (for offboarding)</h2>
        <p>Password manager exports say what is in a vault, not who can open it. Add a CSV with one row per person per vault (or per item). Most admin consoles show this on the vault’s People or Members page; in 1Password Business, the Activity and Users reports list vault access per person.</p>
        <Code label="CSV" code={'person,vault,item,role\nJordan Lee,Marketing & Social,,member\nSofia Alvarez,Marketing & Social,,owner\nJordan Lee,,Office Wi-Fi router admin,member'} />
        <ul className="notes">
          <li><b>role</b> “owner”, “manager” or “admin” makes that person the default owner of rotation steps for the vault.</li>
          <li>No access list? On the Offboarding tab, type a name and tick the items they could open.</li>
        </ul>
      </article>

      <article id="scoring" className="doc-section">
        <h2>Scoring</h2>
        <p>Each item gets 0–100 risk points. The weights are fixed and published:</p>
        <table className="table compact">
          <tbody>
            <tr><td>Password found in breaches (HIBP)</td><td className="num">{WEIGHTS.breached}</td></tr>
            <tr><td>Same password on other items</td><td className="num">{WEIGHTS.reusedBase} + {WEIGHTS.reusedPerExtra} per extra item, max {WEIGHTS.reusedMax}</td></tr>
            <tr><td>Near-reuse (same password with digits or symbols changed)</td><td className="num">{WEIGHTS.nearReuse}</td></tr>
            <tr><td>Strength score 0 / 1 / 2 / 3 / 4 (zxcvbn)</td><td className="num">{WEIGHTS.strength.join(' / ')}</td></tr>
            <tr><td>Not changed in over 1 year / 2 years</td><td className="num">{WEIGHTS.olderThan1y} / {WEIGHTS.olderThan2y}</td></tr>
            <tr><td>Site supports TOTP but none is saved (2fa.directory)</td><td className="num">{WEIGHTS.missing2fa}</td></tr>
            <tr><td>Shared vault, or more than one person in the access list</td><td className="num">{WEIGHTS.sharedVault}</td></tr>
          </tbody>
        </table>
        <p>Severity: critical ≥ 50, high ≥ 25, medium ≥ 10, else low.</p>
        <p><b>Overall health</b> = 100 − ½ × (mean item risk) − ½ × (percent of items rated high or critical). The second term keeps a handful of dangerous items from disappearing inside a large, otherwise clean vault.</p>
        <p><b>Blast radius</b> (offboarding order) = 10 × the accounts that open with this password (the item plus every item sharing it) + the people who need the new password (capped at 10) + risk ÷ 10.</p>
        <p><b>Near-reuse</b>: leading and trailing digits and symbols are stripped, common substitutions (@→a, 0→o, 3→e, $→s) are undone, and passwords with the same letters-only core of 4+ characters are grouped. <code>Summer2024!</code>, <code>Summer2025!</code> and <code>summer-2026</code> all become “summer”.</p>
      </article>

      <article id="checks" className="doc-section">
        <h2>Checks and data sources</h2>
        <ul className="notes">
          <li><b>Breaches</b>: Have I Been Pwned Pwned Passwords range API (free, no key). Only the first 5 hex characters of each password’s SHA-1 are sent, with the <code>Add-Padding</code> header. See <Link href="/security">Security</Link>.</li>
          <li><b>2FA support</b>: the public 2fa.directory dataset (<code>api.2fa.directory/v3/totp.json</code>), matched by registrable domain, so a service listed as <code>mail.google.com</code> or <code>id.atlassian.com</code> covers every login on that domain. Checked on 13 November 2026: 1,294 services (dataset last modified 24 October 2026). If it cannot be reached, a built-in list of about 70 common services, verified against that dataset, is used and the import is labeled “bundled”. Services with only SMS or their own app codes (Apple, most US banks) are not in the TOTP list and are not flagged.</li>
          <li><b>Strength</b>: zxcvbn-ts with its common-password and keyboard dictionaries, loaded only when you import. Synthetic samples use a smaller built-in estimator.</li>
          <li><b>Import formats</b> are tested against the public sample exports in Bitwarden’s importer test suite (<code>github.com/bitwarden/clients</code>, <code>libs/importer/src/importers/spec-data</code>): Chrome (including Android app logins and the newer note column), Firefox (including the Sync-keys row), Safari old and new, 1Password 7 Mac and Windows CSV, and 1PUX logins, passwords, servers, databases, routers, email and API credentials.</li>
          <li><b>SSO candidates</b>: a built-in list of business apps that commonly offer SAML or OIDC SSO, often on a higher plan.</li>
        </ul>
      </article>
    </section>
  )
}
