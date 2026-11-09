import { parseCsv } from './csv.ts'

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
  changed: ['timepasswordchanged', 'password_changed', 'last_changed', 'last changed', 'password last changed', 'modified', 'updated', 'updated_at', 'last_modified', 'lastmodified'],
}

export function detectFormat(header: string[]): Format {
  const h = new Set(header.map(x => x.trim().toLowerCase()))
  const has = (...k: string[]) => k.every(x => h.has(x))
  if (has('login_uri', 'login_password')) return 'bitwarden'
  if (has('url', 'password', 'extra', 'grouping')) return 'lastpass'
  if (has('timepasswordchanged') || has('formactionorigin', 'guid')) return 'firefox'
  if (has('title', 'password', 'otpauth') && (h.has('favorite') || h.has('archived') || h.has('tags'))) return '1password-csv'
  if (has('title', 'url', 'username', 'password', 'otpauth')) return 'apple'
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
  for (const { cells, line } of rows.slice(1)) {
    const get = (f: Field) => (col[f] !== undefined ? cells[col[f]!] ?? '' : '').trim()
    if (cells.length < header.length - 1 && cells.length < 3) { issues.push({ line, level: 'warn', message: `Only ${cells.length} column(s); skipped.` }); continue }
    if (typeCol >= 0 && cells[typeCol] && cells[typeCol] !== 'login') continue
    const password = col.password !== undefined ? cells[col.password] ?? '' : ''
    const url = get('url')
    const title = get('title') || url || get('username')
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
        const loginFields: any[] = it.details?.loginFields ?? []
        const password = loginFields.find(f => f.designation === 'password')?.value ?? it.details?.password ?? ''
        if (!password) continue
        const username = loginFields.find(f => f.designation === 'username')?.value ?? ''
        const totp = (it.details?.sections ?? []).some((s: any) => (s.fields ?? []).some((f: any) => f.value && typeof f.value === 'object' && 'totp' in f.value && f.value.totp))
        const url = it.overview?.url ?? it.overview?.urls?.[0]?.url ?? ''
        const ts = it.updatedAt as number | undefined
        items.push({ line: n, title: it.overview?.title ?? url ?? 'Untitled', url, username, password, totp, vault, shared, changed: ts ? new Date(ts * 1000).toISOString().slice(0, 10) : null })
      }
    }
  }
  if (!items.length) issues.push({ line: 0, level: 'error', message: 'No login items with passwords were found in the archive.' })
  else issues.push({ line: 0, level: 'warn', message: '1PUX has no password-changed date; item “last edited” is used as the age.' })
  return { format: '1password-1pux', items, issues, rows: n, mapping: { title: 'overview.title', url: 'overview.url', password: 'loginFields[password]', vault: 'vault name', changed: 'updatedAt' } }
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
