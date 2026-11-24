import { createHash } from 'node:crypto'
import { deflateRawSync, crc32 } from 'node:zlib'
import { expect, test as base, type Page, type Request } from '@playwright/test'

// ---------------------------------------------------------------------------------------------
// Every credential below is made up. Passwords and usernames carry a distinctive marker so a leak
// into storage, a download or a request can be found by plain substring search.
// ---------------------------------------------------------------------------------------------

export interface Account { vault: string; title: string; url: string; username: string; password: string; totp?: boolean; changed: string }

export const BREACHED_PW = 'Zq-Fixture-Breached-0001'
export const REUSED_PW = 'Zq-Fixture-Reused-Heron-7731'
export const WEAK_PW = 'abc123'

export const ACCOUNTS: Account[] = [
  { vault: 'Marketing', title: 'Fixture Social A', url: 'https://social-a.fixture.example', username: 'zq.alpha@fixture.example', password: REUSED_PW, changed: '2024-03-01' },
  { vault: 'Marketing', title: 'Fixture Social B', url: 'https://social-b.fixture.example', username: 'zq.bravo@fixture.example', password: REUSED_PW, changed: '2024-03-01' },
  { vault: 'Marketing', title: 'Fixture Chat', url: 'https://tfa-site.example', username: 'zq.charlie@fixture.example', password: 'Zq-Fixture-Quartz-Lantern-5582-Xv', changed: '2026-06-01' },
  { vault: 'Operations', title: 'Fixture Router', url: 'http://router.fixture.example', username: 'zq.delta@fixture.example', password: BREACHED_PW, changed: '2019-01-01' },
  { vault: 'Operations', title: 'Fixture Wiki', url: 'https://wiki.fixture.example', username: 'zq.echo@fixture.example', password: WEAK_PW, changed: '2026-02-01' },
  { vault: 'Operations', title: 'Fixture Billing', url: 'https://billing.fixture.example', username: 'zq.foxtrot@fixture.example', password: 'Zq-Fixture-Willow-2024!', changed: '2026-05-01' },
  { vault: 'Operations', title: 'Fixture Billing Backup', url: 'https://billing-backup.fixture.example', username: 'zq.golf@fixture.example', password: 'Zq-Fixture-Willow-2025!', changed: '2026-05-01' },
  { vault: 'Private', title: 'Fixture Private Note Site', url: 'https://private.fixture.example', username: 'zq.hotel@fixture.example', password: 'k7#Rm2$vQp9!wLx4Tz8@nB5c', totp: true, changed: '2026-09-01' },
]

export const SECRETS = ACCOUNTS.flatMap(a => [a.password, a.username])

const csvCell = (v: string) => (/[",\n\r]/.test(v) ? `"${v.replace(/"/g, '""')}"` : v)
export const csv = (rows: string[][]) => rows.map(r => r.map(csvCell).join(',')).join('\n') + '\n'

/** A generic CSV (vault, title, url, username, password, totp, last_changed): the layout the app documents for "any CSV". */
export const vaultCsv = (accounts = ACCOUNTS) =>
  csv([['vault', 'title', 'url', 'username', 'password', 'totp', 'last_changed'], ...accounts.map(a => [a.vault, a.title, a.url, a.username, a.password, a.totp ? 'otpauth://totp/fixture?secret=AAAAAAAAAAAAAAAA' : '', a.changed])])

/** Bitwarden CSV layout (header from Bitwarden's export, see the unit tests). */
export const bitwardenCsv = (accounts = ACCOUNTS) =>
  csv([['folder', 'favorite', 'type', 'name', 'notes', 'fields', 'reprompt', 'login_uri', 'login_username', 'login_password', 'login_totp'],
    ...accounts.map(a => [a.vault, '', 'login', a.title, '', '', '0', a.url, a.username, a.password, a.totp ? 'otpauth://totp/fixture?secret=AAAAAAAAAAAAAAAA' : ''])])

export const accessCsv = csv([
  ['person', 'vault', 'role'],
  ['Fixture Leaver', 'Marketing', 'member'],
  ['Fixture Leaver', 'Operations', 'member'],
  ['Fixture Owner', 'Marketing', 'owner'],
  ['Fixture Owner', 'Operations', 'owner'],
  ['Fixture Colleague', 'Marketing', 'member'],
])

/** 1PUX `export.data` in the shape the importer reads (see src/engine/real-exports.test.ts). */
export const pux1Data = (accounts = ACCOUNTS) => JSON.stringify({
  accounts: [{
    attrs: { accountName: 'Fixture Co' },
    vaults: [...new Set(accounts.map(a => a.vault))].map(v => ({
      attrs: { uuid: `vault-${v}`, name: v, type: v === 'Private' ? 'P' : 'U' },
      items: accounts.filter(a => a.vault === v).map((a, i) => ({
        uuid: `${v}-${i}`, state: 'active', categoryUuid: '001', createdAt: Date.parse(a.changed) / 1000, updatedAt: Date.parse(a.changed) / 1000,
        overview: { title: a.title, url: a.url },
        details: { loginFields: [{ value: a.username, designation: 'username', fieldType: 'T', name: 'username' }, { value: a.password, designation: 'password', fieldType: 'P', name: 'password' }], sections: [] },
      })),
    })),
  }],
})

/** A zip with a single deflated entry, enough for the importer's own zip reader. */
export function zip(name: string, body: string): Buffer {
  const n = Buffer.from(name), raw = Buffer.from(body), data = deflateRawSync(raw), crc = crc32(raw)
  const local = Buffer.alloc(30); local.writeUInt32LE(0x04034b50, 0); local.writeUInt16LE(20, 4); local.writeUInt16LE(8, 8); local.writeUInt32LE(crc, 14); local.writeUInt32LE(data.length, 18); local.writeUInt32LE(raw.length, 22); local.writeUInt16LE(n.length, 26)
  const cen = Buffer.alloc(46); cen.writeUInt32LE(0x02014b50, 0); cen.writeUInt16LE(20, 4); cen.writeUInt16LE(20, 6); cen.writeUInt16LE(8, 10); cen.writeUInt32LE(crc, 16); cen.writeUInt32LE(data.length, 20); cen.writeUInt32LE(raw.length, 24); cen.writeUInt16LE(n.length, 28)
  const end = Buffer.alloc(22); end.writeUInt32LE(0x06054b50, 0); end.writeUInt16LE(1, 8); end.writeUInt16LE(1, 10)
  const head = Buffer.concat([local, n, data])
  end.writeUInt32LE(46 + n.length, 12); end.writeUInt32LE(head.length, 16)
  return Buffer.concat([head, cen, n, end])
}
export const pux = (accounts = ACCOUNTS) => zip('export.data', pux1Data(accounts))

// ---------------------------------------------------------------------------------------------
// Network: the page may only reach the preview server. Breach and 2FA lookups are answered by stubs;
// every other host (fonts, Supabase, anything else) is blocked and recorded.
// ---------------------------------------------------------------------------------------------

const HIBP_HOST = 'api.pwnedpasswords.com'
const TFA_HOST = 'api.2fa.directory'
const sha1 = (s: string) => createHash('sha1').update(s).digest('hex').toUpperCase()

export type BreachMode = 'live' | 'http500' | 'offline' | { failPrefixes: string[] }

export interface Net {
  /** Every request the page made, including the blocked ones. */
  requests: { url: string; method: string; headers: Record<string, string>; body: string }[]
  /** Hosts that were asked for but are neither the app nor a stub. */
  blocked: string[]
  /** Hosts of the stubbed services that were called. */
  stubbed: string[]
  breach: BreachMode
  /** Passwords the fake breach corpus knows about. */
  breachedPasswords: Set<string>
  /** Pageerrors, collected for the whole test. */
  pageErrors: string[]
}

/** A made-up 2fa.directory v3 `totp.json`: 120 filler entries (the app rejects tiny datasets) plus one site the fixtures use. */
const tfaDataset = () => [
  ['Fixture TOTP site', { domain: 'tfa-site.example' }],
  ...Array.from({ length: 120 }, (_, i) => [`Filler ${i}`, { domain: `filler-${i}.example` }]),
]

export const test = base.extend<{ net: Net }>({
  net: [async ({ context, baseURL }, use) => {
    const origin = new URL(baseURL!).origin
    const net: Net = { requests: [], blocked: [], stubbed: [], breach: 'live', breachedPasswords: new Set([BREACHED_PW]), pageErrors: [] }
    const record = (r: Request) => net.requests.push({ url: r.url(), method: r.method(), headers: r.headers(), body: r.postData() ?? '' })
    context.on('request', record)
    context.on('page', p => p.on('pageerror', e => net.pageErrors.push(String(e))))
    await context.route(u => new URL(u).origin !== origin, async route => {
      const u = new URL(route.request().url())
      if (u.hostname === HIBP_HOST && u.pathname.startsWith('/range/')) {
        net.stubbed.push(u.hostname)
        const prefix = u.pathname.slice('/range/'.length).toUpperCase()
        const mode = net.breach
        if (mode === 'offline') return route.abort('internetdisconnected')
        if (mode === 'http500' || (typeof mode === 'object' && mode.failPrefixes.includes(prefix))) return route.fulfill({ status: 500, body: 'stub: server error' })
        const hits = [...net.breachedPasswords].map(sha1).filter(h => h.startsWith(prefix)).map(h => `${h.slice(5)}:42`)
        // Add-Padding responses mix in zero-count lines.
        return route.fulfill({ status: 200, contentType: 'text/plain', body: [...hits, '0000000000000000000000000000000000A:0', '0000000000000000000000000000000000B:0'].join('\r\n') })
      }
      if (u.hostname === TFA_HOST) {
        net.stubbed.push(u.hostname)
        return route.fulfill({ status: 200, contentType: 'application/json', headers: { 'access-control-allow-origin': '*' }, body: JSON.stringify(tfaDataset()) })
      }
      net.blocked.push(u.hostname)
      return route.abort('blockedbyclient')
    })
    await use(net)
    // Applies to every test: no uncaught errors, nothing reached an unexpected host.
    expect(net.pageErrors, 'uncaught page errors').toEqual([])
    expect(net.blocked.filter(h => !/^fonts\.(googleapis|gstatic)\.com$/.test(h)), 'requests to hosts the app should not call').toEqual([])
  }, { auto: true }],
})

export { expect }

// ---------------------------------------------------------------------------------------------
// Page helpers
// ---------------------------------------------------------------------------------------------

/** Everything the app persisted in this browser profile, as one string. */
export async function dumpStorage(page: Page): Promise<string> {
  return page.evaluate(async () => {
    const out: Record<string, unknown> = { localStorage: { ...localStorage }, sessionStorage: { ...sessionStorage } }
    const dbs = await indexedDB.databases()
    out.databases = dbs.map(d => d.name)
    for (const { name } of dbs) {
      if (!name) continue
      const db = await new Promise<IDBDatabase>((res, rej) => { const r = indexedDB.open(name); r.onsuccess = () => res(r.result); r.onerror = () => rej(r.error) })
      const stores: Record<string, unknown> = {}
      for (const s of Array.from(db.objectStoreNames)) {
        stores[s] = await new Promise(res => { const r = db.transaction(s).objectStore(s).getAll(); r.onsuccess = () => res(r.result) })
      }
      out[`idb:${name}`] = stores
      db.close()
    }
    out.caches = await caches.keys()
    return JSON.stringify(out)
  })
}

/** Fails if any made-up credential (or the SHA-1 of a password) shows up in `text`. */
export function expectNoSecrets(text: string, what: string, accounts: Account[] = ACCOUNTS) {
  for (const a of accounts) {
    for (const s of [a.password, a.username]) expect(text, `${what} contains ${s === a.password ? 'a password' : 'a username'} (${s})`).not.toContain(s)
    expect(text.toUpperCase(), `${what} contains the SHA-1 of ${a.password}`).not.toContain(sha1(a.password))
  }
}

export const file = (name: string, content: string | Buffer, mimeType = 'text/csv') => ({ name, mimeType, buffer: Buffer.isBuffer(content) ? content : Buffer.from(content) })

/** Opens a fresh vault and returns the project id from the URL. */
export async function newVault(page: Page): Promise<string> {
  await page.goto('/app')
  await page.getByRole('button', { name: 'Import your data' }).click()
  await page.waitForURL(/\/app\/p\/[\w-]+\/import$/)
  return page.url().match(/\/app\/p\/([\w-]+)\//)![1]
}

/** On the Import tab: choose the vault export, wait for the validation report. */
export async function chooseExport(page: Page, f: ReturnType<typeof file>) {
  await page.locator('input[type=file]').first().setInputFiles(f)
}

/** Imports an export end to end and waits for the overview. */
export async function importExport(page: Page, f: ReturnType<typeof file>) {
  await chooseExport(page, f)
  await expect(page.getByText('Ready', { exact: true })).toBeVisible()
  await page.getByRole('button', { name: /^Analyze \d+ logins?$/ }).click()
  await page.waitForURL(/\/overview$/)
  await expect(page.getByRole('img', { name: /Vault health: \d+ out of 100/ })).toBeVisible()
}

export const healthScore = async (page: Page) => Number((await page.getByRole('img', { name: /Vault health: \d+ out of 100/ }).getAttribute('aria-label'))!.match(/: (\d+) out of/)![1])

/** The number on an Overview stat tile ("Breached", "Reused", ...). */
export async function stat(page: Page, label: string) {
  const tile = page.locator('.stat', { hasText: new RegExp(`^${label}`) })
  return Number(await tile.locator('strong').textContent())
}
