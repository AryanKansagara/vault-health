import { test } from 'node:test'
import assert from 'node:assert/strict'
import { parseCsv, toCsv } from './csv.ts'
import { domainOf, supportsTfa, tfaDomains, TFA_FALLBACK, isSso } from './domain.ts'
import { detectFormat, parse1pux, parseAccess, parseExport, type RawItem } from './formats.ts'
import { analyze, parseRange, quickScore, sha1, skeleton, type Finding } from './analyze.ts'
import { applyFixes, compare, context, fixPlanCsv, offboard, reasons, risk, severity, snapshot, summarize, WEIGHTS } from './risk.ts'
import { entropyBits, generate, SETS } from './password.ts'
import { SAMPLE_BREACHED, SAMPLES, sampleBreaches, sampleFiles } from './sample.ts'
import { readZipEntry } from './unzip.ts'

const NOW = new Date('2026-11-01T00:00:00Z')
const item = (p: Partial<RawItem>): RawItem => ({ line: 2, title: 'Item', url: 'https://example.com', username: 'jo.user@corp.example', password: 'x', totp: false, vault: 'Private', shared: false, changed: null, ...p })
const finding = (p: Partial<Finding>): Finding => ({ id: 'f', title: 'T', domain: 'example.com', vault: 'Private', strength: 4, group: null, near: null, breached: false, changed: '2026-10-01', tfa: false, totp: false, shared: false, sso: false, ...p })

test('csv: quotes, escaped quotes, newlines in fields, CRLF and BOM', () => {
  const rows = parseCsv('﻿a,b\r\n"x, y","he said ""hi"""\n"multi\nline",z\n')
  assert.deepEqual(rows.map(r => r.cells), [['a', 'b'], ['x, y', 'he said "hi"'], ['multi\nline', 'z']])
  assert.deepEqual(rows.map(r => r.line), [1, 2, 3])
})

test('csv: output escapes and neutralises formula injection', () => {
  assert.equal(toCsv([['=HYPERLINK("x")', 'a,b']]), `"'=HYPERLINK(""x"")","a,b"\r\n`)
})

test('detects every supported export format from its header', () => {
  assert.equal(detectFormat(['folder', 'favorite', 'type', 'name', 'notes', 'fields', 'reprompt', 'login_uri', 'login_username', 'login_password', 'login_totp']), 'bitwarden')
  assert.equal(detectFormat(['url', 'username', 'password', 'totp', 'extra', 'name', 'grouping', 'fav']), 'lastpass')
  assert.equal(detectFormat(['name', 'url', 'username', 'password', 'note']), 'chrome')
  assert.equal(detectFormat(['url', 'username', 'password', 'httpRealm', 'formActionOrigin', 'guid', 'timeCreated', 'timeLastUsed', 'timePasswordChanged']), 'firefox')
  assert.equal(detectFormat(['Title', 'Url', 'Username', 'Password', 'OTPAuth', 'Favorite', 'Archived', 'Tags', 'Notes']), '1password-csv')
  assert.equal(detectFormat(['Title', 'URL', 'Username', 'Password', 'Notes', 'OTPAuth']), 'apple')
  assert.equal(detectFormat(['site', 'login', 'secret']), 'generic')
})

test('bitwarden: collections mark shared items, non-login rows are ignored', () => {
  const r = parseExport('collections,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp\nMarketing,login,Insta,,,0,https://instagram.com,me,pw1,otpauth://x\n,note,Secret note,,,0,,,,\n,login,Bank,,,0,https://bank.com,me,pw2,\n')
  assert.equal(r.format, 'bitwarden')
  assert.equal(r.items.length, 2)
  assert.deepEqual([r.items[0].shared, r.items[0].totp, r.items[0].vault], [true, true, 'Marketing'])
  assert.deepEqual([r.items[1].shared, r.items[1].vault], [false, 'Private'])
})

test('firefox: millisecond timestamps become dates; lastpass Shared- folders are shared', () => {
  const ff = parseExport('"url","username","password","httpRealm","formActionOrigin","guid","timeCreated","timeLastUsed","timePasswordChanged"\n"https://a.com","u","p","","","{1}","1","1","1609459200000"\n')
  assert.equal(ff.items[0].changed, '2021-01-01')
  const lp = parseExport('url,username,password,totp,extra,name,grouping,fav\nhttps://x.com,u,p,,,X,Shared-Marketing,0\n')
  assert.equal(lp.items[0].title, 'X')
  assert.equal(lp.items[0].shared, true)
})

test('validation report: missing password column is an error with the columns seen; empty passwords are warnings with line numbers', () => {
  const bad = parseExport('site,login\nx,y\n')
  assert.equal(bad.issues[0].level, 'error')
  assert.match(bad.issues[0].message, /site, login/)
  const warn = parseExport('name,url,username,password\nA,https://a.com,u,\nB,https://b.com,u,p\n')
  assert.equal(warn.items.length, 1)
  assert.deepEqual([warn.issues[0].line, warn.issues[0].level], [2, 'warn'])
})

test('1PUX: vault types, TOTP fields and archived items', () => {
  const r = parse1pux({ accounts: [{ vaults: [
    { attrs: { name: 'Private', type: 'P' }, items: [{ state: 'active', updatedAt: 1609459200, overview: { title: 'Mine', url: 'https://a.com' }, details: { loginFields: [{ designation: 'password', value: 'p1' }], sections: [{ fields: [{ value: { totp: 'otpauth://x' } }] }] } }] },
    { attrs: { name: 'Shared', type: 'U' }, items: [{ state: 'archived', overview: { title: 'Old' }, details: { loginFields: [{ designation: 'password', value: 'p2' }] } }, { overview: { title: 'Team' }, details: { loginFields: [{ designation: 'password', value: 'p3' }] } }] },
  ] }] })
  assert.deepEqual(r.items.map(i => [i.title, i.shared, i.totp]), [['Mine', false, true], ['Team', true, false]])
  assert.equal(r.items[0].changed, '2021-01-01')
})

test('unzip: reads a stored entry out of a zip archive', async () => {
  const name = new TextEncoder().encode('export.data'), body = new TextEncoder().encode('{"ok":1}')
  const local = new Uint8Array(30 + name.length + body.length), lv = new DataView(local.buffer)
  lv.setUint32(0, 0x04034b50, true); lv.setUint32(18, body.length, true); lv.setUint32(22, body.length, true); lv.setUint16(26, name.length, true)
  local.set(name, 30); local.set(body, 30 + name.length)
  const cen = new Uint8Array(46 + name.length), cv = new DataView(cen.buffer)
  cv.setUint32(0, 0x02014b50, true); cv.setUint32(20, body.length, true); cv.setUint32(24, body.length, true); cv.setUint16(28, name.length, true); cv.setUint32(42, 0, true)
  cen.set(name, 46)
  const end = new Uint8Array(22), ev = new DataView(end.buffer)
  ev.setUint32(0, 0x06054b50, true); ev.setUint16(8, 1, true); ev.setUint16(10, 1, true); ev.setUint32(12, cen.length, true); ev.setUint32(16, local.length, true)
  const zip = new Uint8Array([...local, ...cen, ...end])
  const out = await readZipEntry(zip.buffer, 'export.data')
  assert.equal(new TextDecoder().decode(out!), '{"ok":1}')
  assert.equal(await readZipEntry(zip.buffer, 'missing'), null)
})

test('domains: registrable domain, IPs, two-level TLDs, junk', () => {
  assert.equal(domainOf('https://login.mailchimp.com/x?y'), 'mailchimp.com')
  assert.equal(domainOf('www.example.co.uk'), 'example.co.uk')
  assert.equal(domainOf('http://192.168.1.1'), '192.168.1.1')
  assert.equal(domainOf(''), '')
  assert.equal(domainOf('not a url at all'), '')
})

test('2fa.directory parsing and parent-domain matching', () => {
  const set = tfaDomains([['Mailchimp', { domain: 'mailchimp.com', 'additional-domains': ['list-manage.com'] }], ['bad']])
  assert.ok(supportsTfa('mailchimp.com', set) && supportsTfa('list-manage.com', set))
  assert.ok(supportsTfa('login.mailchimp.com', set))
  assert.ok(!supportsTfa('example.com', set))
  assert.ok(TFA_FALLBACK.includes('instagram.com'))
  assert.ok(isSso('github.com') && !isSso('instagram.com'))
})

test('strength: dictionary words with years score low, long random strings score high', () => {
  assert.equal(quickScore('abc'), 0)
  assert.ok(quickScore('Summer2024!') <= 1)
  assert.ok(quickScore('Password1') <= 1)
  assert.equal(quickScore('kT7#vQ2!mZ9@pL4$wX8^'), 4)
  assert.ok(quickScore(generate(20)) >= 3)
})

test('near-reuse skeleton groups seasonal and leetspeak variants', () => {
  assert.equal(skeleton('Summer2024!'), skeleton('Summer2025!'))
  assert.equal(skeleton('P@ssw0rd'), skeleton('password'))
  assert.notEqual(skeleton('Summer2024!'), skeleton('Winter2024!'))
})

test('analyze: exact and near reuse groups, stable ids, no plaintext in output', async () => {
  const items = [
    item({ title: 'A', url: 'https://a.com', password: 'Shared#Pw2021' }),
    item({ title: 'B', url: 'https://b.com', password: 'Shared#Pw2021' }),
    item({ title: 'C', url: 'https://c.com', password: 'Shared#Pw2022' }),
    item({ title: 'D', url: 'https://d.com', password: 'unique-and-long-one' }),
  ]
  const fs = await analyze(items)
  assert.ok(fs[0].group && fs[0].group === fs[1].group)
  assert.equal(fs[2].group, null)
  assert.ok(fs[2].near && fs[2].near === fs[0].near)
  assert.equal(fs[3].group, null); assert.equal(fs[3].near, null)
  const again = await analyze(items)
  assert.deepEqual(fs.map(f => f.id), again.map(f => f.id), 'item ids are stable across imports')
  assert.notEqual(fs[0].group, again[0].group, 'reuse ids use a fresh salt per import')
  const json = JSON.stringify(fs)
  for (const it of items) assert.ok(!json.includes(it.password), 'no password in findings')
  assert.ok(!json.includes('jo.user@corp.example'), 'no username in findings')
})

test('analyze: breach map, 2FA availability, duplicate item ids', async () => {
  const items = [item({ password: 'Password1', url: 'https://instagram.com' }), item({ password: 'Password1', url: 'https://instagram.com' })]
  const fs = await analyze(items, { breached: new Map([[await sha1('Password1'), true]]), tfa: new Set(['instagram.com']) })
  assert.deepEqual([fs[0].breached, fs[0].tfa, fs[0].totp], [true, true, false])
  assert.notEqual(fs[0].id, fs[1].id)
  const unchecked = await analyze([item({ password: 'zzz' })])
  assert.equal(unchecked[0].breached, null)
})

test('HIBP range parsing ignores padding rows and prefixes the suffix', async () => {
  const set = parseRange('5baa6', '1E4C9B93F3F0682250B6CF8331B7EE68FD8:3861493\r\nFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF:0\r\n')
  assert.ok(set.has('5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8'))
  assert.equal(set.size, 1)
  assert.equal(await sha1('password'), '5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8')
})

test('risk: weights add up per documented rule and cap at 100', () => {
  const fs = [finding({ id: 'a', group: 'g', breached: true, strength: 0, changed: '2020-01-01', tfa: true, shared: true }), finding({ id: 'b', group: 'g' }), finding({ id: 'c', group: 'g' })]
  const ctx = context(fs, [], NOW)
  const r = reasons(fs[0], ctx)
  const expect = WEIGHTS.breached + (WEIGHTS.reusedBase + WEIGHTS.reusedPerExtra) + WEIGHTS.strength[0] + WEIGHTS.olderThan2y + WEIGHTS.missing2fa + WEIGHTS.sharedVault
  assert.equal(r.reduce((a, x) => a + x.points, 0), expect)
  assert.equal(risk(fs[0], ctx), Math.min(100, expect))
  assert.equal(risk(finding({}), ctx), 0)
  assert.equal(severity(risk(fs[0], ctx)), 'critical')
})

test('risk: access list makes a vault shared; near reuse only counts without exact reuse', () => {
  const fs = [finding({ id: 'a', vault: 'Ops', near: 'n' }), finding({ id: 'b', vault: 'Ops', near: 'n' })]
  const ctx = context(fs, [{ person: 'x', vault: 'Ops', item: '', role: 'member' }, { person: 'y', vault: 'Ops', item: '', role: 'owner' }], NOW)
  assert.deepEqual(reasons(fs[0], ctx).map(r => r.key), ['nearReuse', 'sharedVault'])
})

test('health: a clean vault is 100, a few critical items pull it down hard', () => {
  const clean = Array.from({ length: 20 }, (_, i) => finding({ id: String(i) }))
  assert.equal(summarize(clean, context(clean, [], NOW)).health, 100)
  const dirty = [...clean.slice(0, 18), finding({ id: 'x', breached: true, strength: 0 }), finding({ id: 'y', breached: true, strength: 0 })]
  const s = summarize(dirty, context(dirty, [], NOW))
  assert.ok(s.health < 95 && s.health > 80, `health ${s.health}`)
  assert.equal(s.breached, 2); assert.equal(s.bySeverity.critical, 2)
})

test('rotating an item heals it and its reuse partner', () => {
  const fs = [finding({ id: 'a', group: 'g', strength: 1 }), finding({ id: 'b', group: 'g', strength: 1 })]
  const before = summarize(fs, context(fs, [], NOW)).health
  const fixed = applyFixes(fs, { a: '2026-11-01' })
  assert.equal(fixed[0].group, null)
  const after = summarize(fixed, context(fixed, [], NOW))
  assert.ok(after.health > before)
  assert.equal(after.reused, 0, 'b is no longer reused once a is rotated')
  assert.equal(applyFixes([finding({ id: 'a', changed: '2026-12-01', strength: 0 })], { a: '2026-11-01' })[0].strength, 0, 'a newer import wins over an older fix mark')
})

test('offboarding: reachable items ordered by blast radius with owners and siblings', () => {
  const fs = [finding({ id: 'social', title: 'Instagram', vault: 'Social', group: 'g' }), finding({ id: 'fb', title: 'Facebook', vault: 'Social', group: 'g' }), finding({ id: 'bank', title: 'Bank', vault: 'Finance' }), finding({ id: 'solo', title: 'Router', vault: 'Private' })]
  const access = parseAccess('person,vault,role\nJo,Social,member\nAl,Social,owner\nBe,Social,member\nJo,Finance,member\n').rows
  const steps = offboard('Jo', fs, access, context(fs, access, NOW), ['solo'])
  assert.ok(['fb', 'social'].includes(steps[0].finding.id), 'the shared password comes first')
  assert.equal(steps[0].owner, 'Al')
  assert.equal(steps[0].audience, 2)
  assert.equal(steps[0].also.length, 1)
  assert.ok(steps.some(s => s.finding.id === 'solo' && s.owner === 'Unassigned'))
  assert.equal(steps.length, 3, 'reuse siblings collapse into one step')
})

test('access list: role detection and validation', () => {
  const r = parseAccess('email,collection,permission\na@x.com,Ops,Manage\nb@x.com,,view\n')
  assert.deepEqual(r.rows, [{ person: 'a@x.com', vault: 'Ops', item: '', role: 'owner' }])
  assert.equal(r.issues[0].line, 3)
  assert.equal(parseAccess('foo\n1\n').issues[0].level, 'error')
})

test('snapshots compare: fixed, worse, added, removed', () => {
  const a = [finding({ id: 'x', breached: true }), finding({ id: 'y' }), finding({ id: 'gone', breached: true })]
  const b = [finding({ id: 'x' }), finding({ id: 'y', breached: true, strength: 0 }), finding({ id: 'new' })]
  const d = compare(snapshot(a, context(a, [], NOW), '1', 'Q3'), snapshot(b, context(b, [], NOW), '2', 'Q4'))
  assert.deepEqual(d.fixed.sort(), ['gone', 'x'])
  assert.deepEqual(d.worse, ['y'])
  assert.deepEqual(d.added, ['new'])
  assert.deepEqual(d.removed, ['gone'])
})

test('fix plan CSV is sorted by risk and explains each row', () => {
  const fs = [finding({ id: 'a', title: 'Low', strength: 2 }), finding({ id: 'b', title: 'High', breached: true, strength: 0 })]
  const rows = parseCsv(fixPlanCsv(fs, context(fs, [], NOW)))
  assert.equal(rows[1].cells[1], 'High')
  assert.match(rows[1].cells[14], /Rotate/)
  assert.equal(rows.length, 3)
})

test('password generator: length, character classes, no look-alikes, uniqueness', () => {
  const pw = generate(24)
  assert.equal(pw.length, 24)
  for (const s of Object.values(SETS)) assert.ok([...pw].some(c => s.includes(c)))
  assert.ok(!/[lIO01]/.test(generate(200)))
  assert.equal(new Set(Array.from({ length: 200 }, () => generate(16))).size, 200)
  assert.equal(generate(3, ['digits']).length, 3)
  assert.ok(entropyBits(24, ['lower', 'upper', 'digits', 'symbols']) > 140)
})

test('agency sample: six-site social reuse, breached and old passwords, departing person', async () => {
  const { vault, access } = sampleFiles('agency', 'now', NOW)
  const parsed = parseExport(vault)
  assert.equal(parsed.issues.length, 0)
  const fs = await analyze(parsed.items, { breached: await sampleBreaches(parsed.items), tfa: new Set(TFA_FALLBACK) })
  const ctx = context(fs, parseAccess(access).rows, NOW)
  const groups = new Map<string, number>()
  for (const f of fs) if (f.group) groups.set(f.group, (groups.get(f.group) ?? 0) + 1)
  assert.equal(Math.max(...groups.values()), 6)
  const s = summarize(fs, ctx)
  assert.ok(s.breached >= 4 && s.old >= 8 && s.near >= 2, JSON.stringify(s))
  assert.ok(s.health < 60, `health ${s.health}`)
  const plan = offboard(SAMPLES[0].departing, fs, parseAccess(access).rows, ctx)
  assert.ok(plan[0].also.length >= 5, 'the shared social login is first')
})

test('samples: every sample parses cleanly, improves over the quarter, and uses fake passwords', async () => {
  for (const s of SAMPLES) {
    const now = parseExport(sampleFiles(s.id, 'now', NOW).vault), before = parseExport(sampleFiles(s.id, 'before', NOW).vault)
    assert.ok(now.items.length >= 12)
    const h = async (items: RawItem[]) => { const fs = await analyze(items, { breached: await sampleBreaches(items) }); return summarize(fs, context(fs, parseAccess(sampleFiles(s.id).access).rows, NOW)).health }
    assert.ok(await h(now.items) > await h(before.items), s.id)
    assert.ok(now.items.every(i => i.username.endsWith('.example')))
  }
  assert.ok(SAMPLE_BREACHED.size >= 5)
})
