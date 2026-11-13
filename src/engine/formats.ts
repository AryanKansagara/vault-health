import { parseCsv } from './csv.ts'
import { siteName } from './domain.ts'

/** One parsed login. Holds the plaintext password, so it only ever lives in memory. */
export interface RawItem {
  line: number
  title: string
  url: string
  username: string
  password: string
  totp: boolean
  vault: string
  /** True when the export itself says the item sits in a shared vault/collection/folder. */
  shared: boolean
  /** ISO date of the last password change, when the export has one. */
  changed: string | null
}

export type Format = '1password-csv' | '1password-1pux' | 'bitwarden' | 'lastpass' | 'chrome' | 'firefox' | 'apple' | 'generic'

export const FORMAT_LABEL: Record<Format, string> = {
  '1password-csv': '1Password (CSV)',
  '1password-1pux': '1Password (1PUX)',
  bitwarden: 'Bitwarden (CSV)',
  lastpass: 'LastPass (CSV)',
  chrome: 'Chrome / Edge (CSV)',
  firefox: 'Firefox (CSV)',
  apple: 'Apple Passwords (CSV)',
  generic: 'Generic CSV',
}

export interface Issue { line: number; level: 'error' | 'warn'; message: string }

export interface ParseResult {
  format: Format
  items: RawItem[]
  issues: Issue[]
  /** Rows read (excluding header). */
  rows: number
  /** Column used for each field, for the validation report. */
  mapping: Partial<Record<Field, string>>
}

type Field = 'title' | 'url' | 'username' | 'password' | 'totp' | 'vault' | 'changed'

const SYN: Record<Field, string[]> = {
  title: ['title', 'name', 'item', 'item name', 'account', 'site'],
  url: ['url', 'login_uri', 'website', 'uri', 'urls', 'web site', 'login url', 'hostname'],
  username: ['username', 'login_username', 'user', 'login', 'email', 'user name'],
  password: ['password', 'login_password', 'pass', 'secret'],
  totp: ['otpauth', 'totp', 'login_totp', 'otp', 'one-time password', '2fa', 'mfa'],
  vault: ['vault', 'collections', 'folder', 'grouping', 'group', 'collection', 'category'],
  changed: ['timepasswordchanged', 'password_changed', 'last_changed', 'last changed', 'password last changed', 'modified', 'updated', 'updated_at', 'last_modified', 'lastmodified', 'modified date'],
}

export function detectFormat(header: string[]): Format {
  const h = new Set(header.map(x => x.trim().toLowerCase()))
  const has = (...k: string[]) => k.every(x => h.has(x))
  if (has('login_uri', 'login_password')) return 'bitwarden'
  if (has('url', 'password', 'extra', 'grouping')) return 'lastpass'
  if (has('timepasswordchanged') || has('formactionorigin', 'guid')) return 'firefox'
  if (has('title', 'password', 'otpauth') && (h.has('favorite') || h.has('archived') || h.has('tags'))) return '1password-csv'
  // 1Password 7 "all fields" exports: Mac writes Type/Modified Date, Windows writes UUID/Scope/Autosubmit.
  if (has('title', 'password', 'type', 'modified date') || has('uuid', 'title', 'password', 'scope')) return '1password-csv'
  if (has('title', 'url', 'username', 'password', 'otpauth')) return 'apple'
  // Safari before macOS 12 wrote only these four columns.
  if (has('title', 'url', 'username', 'password') && h.size === 4) return 'apple'
  if (has('name', 'url', 'username', 'password') && h.size <= 5) return 'chrome'
  return 'generic'
}

const SHARED_HINT = /^(shared|team|company|everyone|marketing|ops|it|finance|social)/i

function toIso(v: string): string | null {
  const s = v.trim()
  if (!s) return null
  const n = Number(s)
  // Firefox writes milliseconds since epoch; some tools write seconds.
  const d = Number.isFinite(n) && /^\d+$/.test(s) ? new Date(n > 1e12 ? n : n * 1000) : new Date(s)
  return Number.isNaN(d.getTime()) || d.getUTCFullYear() < 1995 ? null : d.toISOString().slice(0, 10)
}

export function parseExport(text: string, forced?: Format): ParseResult {
  const rows = parseCsv(text)
  const issues: Issue[] = []
  if (!rows.length) return { format: forced ?? 'generic', items: [], issues: [{ line: 1, level: 'error', message: 'The file is empty.' }], rows: 0, mapping: {} }
  const header = rows[0].cells.map(x => x.trim())
  const format = forced ?? detectFormat(header)
  const lower = header.map(x => x.toLowerCase())
  const mapping: Partial<Record<Field, string>> = {}
  const col: Partial<Record<Field, number>> = {}
  for (const f of Object.keys(SYN) as Field[]) {
    const i = SYN[f].map(s => lower.indexOf(s)).find(i => i >= 0)
    if (i !== undefined) { col[f] = i; mapping[f] = header[i] }
  }
  if (format === 'lastpass' && lower.includes('name')) { col.title = lower.indexOf('name'); mapping.title = header[col.title] }
  if (col.password === undefined) {
    issues.push({ line: 1, level: 'error', message: `No password column found. Columns seen: ${header.join(', ') || '(none)'}.` })
    return { format, items: [], issues, rows: rows.length - 1, mapping }
  }
  const items: RawItem[] = []
  const typeCol = format === 'bitwarden' ? lower.indexOf('type') : -1
  // Non-login rows (secure notes, cards, identities) carry no password; skip them quietly instead of warning on each.
  const kindCol = format === '1password-csv' ? lower.indexOf('type') : -1
  const archivedCol = format === '1password-csv' ? lower.indexOf('archived') : -1
  for (const { cells, line } of rows.slice(1)) {
    const get = (f: Field) => (col[f] !== undefined ? cells[col[f]!] ?? '' : '').trim()
    if (cells.length < header.length - 1 && cells.length < 3) { issues.push({ line, level: 'warn', message: `Only ${cells.length} column(s); skipped.` }); continue }
    if (typeCol >= 0 && cells[typeCol] && cells[typeCol] !== 'login') continue
    if (archivedCol >= 0 && /^true$/i.test(cells[archivedCol] ?? '')) continue
    const password = col.password !== undefined ? cells[col.password] ?? '' : ''
    const url = get('url')
    // Firefox stores its own sync keys as a "login" for chrome://FirefoxAccounts; it is not a site password.
    if (/^(chrome|about|moz-extension|chrome-extension):/i.test(url)) continue
    const title = get('title') || (url && siteName(url)) || get('username')
    if (!password && kindCol >= 0 && !/^(login|password)$/i.test(cells[kindCol] ?? '')) continue
    if (!password) { issues.push({ line, level: 'warn', message: `“${title || 'Untitled'}” has no password; skipped.` }); continue }
    let vault = get('vault')
    let shared = false
    if (format === 'bitwarden') shared = lower.includes('collections') && !!vault
    else if (format === 'lastpass') shared = /^shared[-\s]/i.test(vault)
    else shared = SHARED_HINT.test(vault)
    if (!vault) vault = format === 'chrome' ? 'Browser' : format === 'firefox' ? 'Firefox' : format === 'apple' ? 'Apple Passwords' : 'Private'
    const changedRaw = get('changed')
    const changed = changedRaw ? toIso(changedRaw) : null
    if (changedRaw && !changed) issues.push({ line, level: 'warn', message: `Could not read the date “${changedRaw}”; age is unknown for this item.` })
    items.push({ line, title: title || 'Untitled', url, username: get('username'), password, totp: !!get('totp'), vault, shared, changed })
  }
  if (!items.length && !issues.some(i => i.level === 'error')) issues.push({ line: 1, level: 'error', message: 'No logins with passwords were found.' })
  return { format, items, issues, rows: rows.length - 1, mapping }
}

/** Section field ids that hold a reusable secret in 1Password's non-login categories (not PINs, CVVs or ID numbers). */
const SECRET_FIELD = /^(password|admin_console_password|wireless_password|disk_password|pop_password|smtp_password|credential)$/

/** Parses the export.data JSON inside a .1pux archive. */
export function parse1pux(json: unknown): ParseResult {
  const items: RawItem[] = []
  const issues: Issue[] = []
  let n = 0
  const accounts = (json as { accounts?: unknown[] })?.accounts
  if (!Array.isArray(accounts)) return { format: '1password-1pux', items, issues: [{ line: 0, level: 'error', message: 'This does not look like a 1PUX export (no accounts).' }], rows: 0, mapping: {} }
  for (const acc of accounts as { vaults?: { attrs?: { name?: string; type?: string }; items?: unknown[] }[] }[]) {
    for (const v of acc.vaults ?? []) {
      const vault = v.attrs?.name ?? 'Vault'
      const shared = v.attrs?.type === 'E' || v.attrs?.type === 'U'
      for (const it of (v.items ?? []) as Record<string, any>[]) {
        n++
        if (it.state === 'archived') continue
        const fields: any[] = (it.details?.sections ?? []).flatMap((s: any) => (s.fields ?? []).map((f: any) => ({ ...f, section: s.title ?? '' })))
        const str = (...ids: string[]) => ids.map(id => fields.find(f => f.id === id)?.value?.string).find(Boolean) ?? ''
        const totp = fields.some(f => f.value && typeof f.value === 'object' && f.value.totp)
        const title: string = it.overview?.title || 'Untitled'
        const history: { time?: number }[] = it.details?.passwordHistory ?? []
        // The newest history entry is when the current password was set; with no history it has not changed since the item was created.
        const ts = Math.max(0, ...history.map(h => h.time ?? 0)) || it.createdAt || it.updatedAt
        const changed = ts ? new Date(ts * 1000).toISOString().slice(0, 10) : null
        const loginFields: any[] = it.details?.loginFields ?? []
        const password = loginFields.find(f => f.designation === 'password')?.value ?? it.details?.password ?? ''
        if (password) {
          const url = it.overview?.url || it.overview?.urls?.[0]?.url || ''
          const username = loginFields.find(f => f.designation === 'username')?.value ?? ''
          items.push({ line: n, title: it.overview?.title || (url && siteName(url)) || 'Untitled', url, username, password, totp, vault, shared, changed })
          continue
        }
        // Server, database, router, email and API credential items keep their secrets in section fields. They are exactly
        // the shared credentials an offboarding has to rotate, so each one becomes its own item.
        const secrets = fields.filter(f => SECRET_FIELD.test(f.id ?? '') && typeof f.value?.concealed === 'string' && f.value.concealed)
        const url = str('url', 'admin_console_url', 'website', 'hostname', 'server', 'pop_server')
        const username = str('username', 'pop_username', 'admin_console_username')
        for (const f of secrets) {
          const label = secrets.length > 1 ? ` (${[f.section, f.title || f.id].filter(Boolean).join(' ')})` : ''
          items.push({ line: n, title: title + label, url, username, password: f.value.concealed, totp, vault, shared, changed })
        }
      }
    }
  }
  if (!items.length) issues.push({ line: 0, level: 'error', message: 'No login items with passwords were found in the archive.' })
  return { format: '1password-1pux', items, issues, rows: n, mapping: { title: 'overview.title', url: 'overview.url', password: 'loginFields[password] or concealed password fields', vault: 'vault name', changed: 'passwordHistory, else createdAt' } }
}

/** Who can open which vault (or item). CSV columns: person (or email/user), vault, item (optional), role (optional: owner/manager/member). */
export interface Access { person: string; vault: string; item: string; role: 'owner' | 'member' }

export function parseAccess(text: string): { rows: Access[]; issues: Issue[] } {
  const rows = parseCsv(text)
  const issues: Issue[] = []
  if (!rows.length) return { rows: [], issues: [{ line: 1, level: 'error', message: 'The file is empty.' }] }
  const h = rows[0].cells.map(x => x.trim().toLowerCase())
  const find = (...k: string[]) => k.map(x => h.indexOf(x)).find(i => i >= 0) ?? -1
  const pc = find('person', 'name', 'email', 'user', 'member')
  const vc = find('vault', 'collection', 'group', 'folder', 'shared folder')
  const ic = find('item', 'title', 'login')
  const rc = find('role', 'permission', 'access')
  if (pc < 0 || (vc < 0 && ic < 0)) return { rows: [], issues: [{ line: 1, level: 'error', message: 'Need a person column and a vault or item column.' }] }
  const out: Access[] = []
  for (const { cells, line } of rows.slice(1)) {
    const person = (cells[pc] ?? '').trim()
    const vault = vc >= 0 ? (cells[vc] ?? '').trim() : ''
    const item = ic >= 0 ? (cells[ic] ?? '').trim() : ''
    if (!person || (!vault && !item)) { issues.push({ line, level: 'warn', message: 'Missing person or vault/item; skipped.' }); continue }
    const role = /owner|manage|admin/i.test(cells[rc] ?? '') ? 'owner' : 'member'
    out.push({ person, vault, item, role })
  }
  return { rows: out, issues }
}
