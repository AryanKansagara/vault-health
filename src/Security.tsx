import { useSyncExternalStore } from 'react'
import { clearImport, heldImport, HIBP_URL, subscribeHeld, TFA_URL } from './checks.ts'
import { Code, Link, plural, toast } from './ui.tsx'

export default function Security() {
  const held = useSyncExternalStore(subscribeHeld, heldImport)
  return (
    <section className="page narrow docs">
      <div className="eyebrow">Security</div>
      <h1>How Vault Health handles your passwords</h1>
      <p className="lede">Short version: the export file is read inside this browser tab, passwords are used to compute a handful of derived facts, and only those facts are kept. Nothing secret is written to disk, local storage or the cloud.</p>

      <div className={`panel held-panel${held ? ' on' : ''}`}>
        <h2>Imported file in memory</h2>
        {held ? (
          <>
            <p><b>{held.fileName}</b> ({plural(held.items.length, 'login')}) is held in this tab’s memory so you can re-check it without picking the file again.</p>
            <button type="button" className="btn primary" onClick={() => { clearImport(); toast('Cleared from memory', { tone: 'ok' }) }}>Clear the imported file from memory</button>
          </>
        ) : <p className="muted">Nothing is held right now. Closing or reloading the tab also clears it.</p>}
        <p className="muted small">JavaScript strings cannot be overwritten in place. Clearing drops every reference so the browser can reclaim the memory; for full assurance, close the tab.</p>
      </div>

      <article className="doc-section">
        <h2>What is stored</h2>
        <p>Per item, and nothing else:</p>
        <Code label="Finding" code={`{
  id:       "3f9a0c1b7e2d",    // SHA-256 of vault|title|domain|username, first 12 hex
  title:    "Instagram (brand)",
  domain:   "instagram.com",   // registrable domain only, no path or query
  vault:    "Marketing & Social",
  strength: 1,                 // 0-4
  group:    "a1b2c3d4",        // reuse group, see below; null if unique
  near:     null,              // near-reuse group
  breached: true,              // or false / null (not checked)
  changed:  "2021-05-14",
  tfa:      true,              // the site supports TOTP
  totp:     false,             // a TOTP is saved with the item
  shared:   true,
  sso:      false
}`} />
        <ul className="notes">
          <li>No password, no username, no notes, no TOTP secret, no full URL.</li>
          <li><b>Reuse ids</b> are the first 8 hex characters (32 bits) of SHA-256(random salt + password). The salt is made fresh for each import and thrown away when the analysis finishes, so the ids cannot be tested against guesses later, and 32 bits is far too short to identify a password anyway.</li>
          <li>The item id includes the username in its hash so two logins on one site stay separate. It is a one-way hash of non-secret fields.</li>
          <li>Generated replacement passwords exist only in the dialog that shows them.</li>
        </ul>
      </article>

      <article className="doc-section">
        <h2>Where it is stored</h2>
        <ul className="notes">
          <li><b>This device</b>: findings, offboarding progress and snapshots in IndexedDB. Theme and settings in localStorage.</li>
          <li><b>Cloud (optional)</b>: if you sign in, the same derived findings sync to a Supabase Postgres table protected by row-level security, so only your account can read your rows. Delete your cloud data or your whole account from the account menu at any time.</li>
        </ul>
      </article>

      <article className="doc-section">
        <h2>Breach check: k-anonymity</h2>
        <p>For each unique password, the browser computes its SHA-1 and sends only the first 5 hex characters to <code>{HIBP_URL}</code> with <code>Add-Padding: true</code>. The service returns every known hash suffix with that prefix (hundreds, plus random padding rows so the response size reveals nothing). The match happens locally. Have I Been Pwned never sees a password or a full hash.</p>
        <Code label="Example" code={`SHA-1("password") = 5BAA6 1E4C9B93F3F0682250B6CF8331B7EE68FD8
GET ${HIBP_URL}5BAA6      ← only this leaves the browser
…1E4C9B93F3F0682250B6CF8331B7EE68FD8:3,861,493   ← matched locally`} />
        <p>Turn the check off in <Link href="/settings">Settings</Link> if you would rather not make the requests; items are then marked “unchecked”.</p>
      </article>

      <article className="doc-section">
        <h2>2FA dataset</h2>
        <p>The page downloads the public 2fa.directory list once (<code>{TFA_URL}</code>) and matches domains locally. No item data is sent.</p>
      </article>

      <article className="doc-section">
        <h2>Content Security Policy</h2>
        <p>The site ships a strict CSP: scripts only from this origin, no inline scripts except one hashed theme snippet, no plugins, no framing. Network access is limited to:</p>
        <ul className="notes">
          <li><code>api.pwnedpasswords.com</code> (breach ranges)</li>
          <li><code>api.2fa.directory</code> (2FA dataset)</li>
          <li>the Supabase project, only if you sign in</li>
          <li>Google Fonts for typefaces</li>
        </ul>
        <p>Even a bug in this app could not post your data anywhere else.</p>
      </article>

      <article className="doc-section">
        <h2>What this cannot protect against</h2>
        <ul className="notes">
          <li>Browser extensions with permission to read every page can read this one too. Use a clean browser profile for the import if that worries you.</li>
          <li>The export file on your disk is plain text. Delete it (and empty the trash) when you are done.</li>
          <li>A compromised computer. If the machine is not trusted, neither is the password manager on it.</li>
        </ul>
      </article>
    </section>
  )
}
