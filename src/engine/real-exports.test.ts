// Fixtures below follow the exact layout of real exports, as published in Bitwarden's importer test data
// (github.com/bitwarden/clients, libs/importer/src/importers/spec-data). Values are rewritten and fake.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { domainOf, supportsTfa, tfaDomains, TFA_FALLBACK } from './domain.ts'
import { detectFormat, parse1pux, parseExport } from './formats.ts'

test('chrome: Android app logins get the package as title and a usable domain', () => {
  const r = parseExport('name,url,username,password\n,android://N2H9MndUUUt3JuQSWAKexOU9oJLJeHR4nyUGac5E1TXKppkY7xtdRl6l8vKo1hQWCqAEy4gsNLUBIbVxpdmhOP==@com.slack/,jo@corp.example,fake-pw-1\n')
  assert.equal(r.format, 'chrome')
  assert.equal(r.items[0].title, 'com.slack')
  assert.equal(domainOf(r.items[0].url), 'slack.com')
  assert.equal(domainOf('androidapp://com.facebook.katana'), 'facebook.com')
})

test('chrome: current export with a note column, CRLF and a multi-line quoted note', () => {
  const r = parseExport('name,url,username,password,note\r\nwww.example.com,https://www.example.com/,jo@corp.example,fake-pw,"First line, with a comma\r\nSecond line with ""quotes"""\r\n')
  assert.equal(r.format, 'chrome')
  assert.equal(r.items.length, 1)
  assert.deepEqual(r.issues, [])
})

test('firefox: the chrome://FirefoxAccounts sync-key row is skipped and titles are host names', () => {
  const r = parseExport('"url","username","password","httpRealm","formActionOrigin","guid","timeCreated","timeLastUsed","timePasswordChanged"\n' +
    '"chrome://FirefoxAccounts","0123456789abcdef","{""version"":1,""accountData"":{""kSync"":""xx""}}",,"Firefox Accounts credentials","{a1}","1612345678900","1612345678900","1612345678900"\n' +
    '"https://www.example.com","foo","bar",,"https://www.example.com","{b2}","1612345678900","1612345678900","1612345678900"\n')
  assert.deepEqual(r.items.map(i => [i.title, i.changed]), [['example.com', '2021-02-03']])
  assert.deepEqual(r.issues, [])
})

test('safari: the old four-column export is recognised as Apple Passwords', () => {
  assert.equal(detectFormat(['Title', 'Url', 'Username', 'Password']), 'apple')
  assert.equal(parseExport('Title,Url,Username,Password\nexample.com (jo),https://example.com,jo,fake-p@ss\n').items[0].vault, 'Apple Passwords')
})

test('1Password 7 Mac CSV: detected, Modified Date is the age, cards and notes skipped quietly', () => {
  const head = '"Created Date","Modified Date","Notes","Password","Title","Type","URL","Username"'
  const r = parseExport(`${head}\n"1606923754","1606923754","Follow these steps","","Welcome to 1Password!","Secure Note","",""\n"1606923869","1607355631","","","test card","Credit Card","",""\n"1606923754","1607020972","","fake-account-pw","1Password Account","Login","https://my.1password.com","jo@corp.example"\n`)
  assert.equal(r.format, '1password-csv')
  assert.deepEqual(r.items.map(i => [i.title, i.changed]), [['1Password Account', '2020-12-03']])
  assert.deepEqual(r.issues, [])
})

test('1Password 7 Windows CSV and 1Password 8 CSV: detected; archived rows skipped', () => {
  assert.equal(detectFormat(['UUID', 'TITLE', 'USERNAME', 'PASSWORD', 'URL', 'URLS', 'EMAIL', 'MASTER-PASSWORD', 'ACCOUNT-KEY', 'SCOPE', 'AUTOSUBMIT', 'TAGS', 'NOTES']), '1password-csv')
  const r = parseExport('Title,Url,Username,Password,OTPAuth,Favorite,Archived,Tags,Notes\nLive,https://a.com,u,p1,,false,false,,\nGone,https://b.com,u,p2,,false,true,,\n')
  assert.deepEqual(r.items.map(i => i.title), ['Live'])
})

test('bitwarden: several URIs in login_uri use the first one', () => {
  const r = parseExport('folder,favorite,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp\n,,login,Google,,,0,"https://accounts.google.com,https://mail.google.com",jo,fake-pw,\n')
  assert.equal(domainOf(r.items[0].url), 'google.com')
})

const pux = (items: unknown[]) => ({ accounts: [{ attrs: { name: 'Jo' }, vaults: [{ attrs: { uuid: 'v1', name: 'Ops', type: 'U' }, items }] }] })

test('1PUX: age comes from password history, else creation, not the last edit', () => {
  const login = (title: string, extra: object) => ({ uuid: title, state: 'active', categoryUuid: '001', createdAt: 1577836800, updatedAt: 1735689600, overview: { title, url: 'https://a.com' }, details: { loginFields: [{ value: 'pw-' + title, designation: 'password', fieldType: 'P', name: 'password' }], sections: [], ...extra } })
  const r = parse1pux(pux([
    login('Changed', { passwordHistory: [{ value: 'old2', time: 1640995200 }, { value: 'old1', time: 1609459200 }] }),
    login('Never', { passwordHistory: [] }),
  ]))
  assert.deepEqual(r.items.map(i => i.changed), ['2022-01-01', '2020-01-01'])
})

test('1PUX: server, router and API credential items become rotation rows; PINs and card numbers do not', () => {
  const f = (id: string, title: string, value: object) => ({ id, title, value })
  const r = parse1pux(pux([
    { state: 'active', categoryUuid: '110', createdAt: 1619465117, overview: { title: 'Prod Server', url: '' }, details: { loginFields: [], sections: [
      { title: '', fields: [f('url', 'URL', { string: 'https://srv.corp.example' }), f('username', 'username', { string: 'deploy' }), f('password', 'password', { concealed: 'fake-srv-pw' })] },
      { title: 'Admin Console', fields: [f('admin_console_password', 'console password', { concealed: 'fake-console-pw' })] },
    ] } },
    { state: 'active', categoryUuid: '112', createdAt: 1619466056, overview: { title: 'Stripe key' }, details: { sections: [{ fields: [f('credential', 'credential', { concealed: 'fake-key' }), f('hostname', 'hostname', { string: 'api.stripe.com' })] }] } },
    { state: 'active', categoryUuid: '101', createdAt: 1619466056, overview: { title: 'Bank Account' }, details: { sections: [{ fields: [f('telephonePin', 'telephone PIN', { concealed: '1234' })] }] } },
    { state: 'active', categoryUuid: '002', createdAt: 1619466056, overview: { title: 'Card' }, details: { sections: [{ fields: [f('cvv', 'verification number', { concealed: '123' }), f('pin', 'PIN', { concealed: '9999' })] }] } },
  ]))
  assert.deepEqual(r.items.map(i => [i.title, domainOf(i.url), i.username, i.shared]), [
    ['Prod Server (password)', 'corp.example', 'deploy', true],
    ['Prod Server (Admin Console console password)', 'corp.example', 'deploy', true],
    ['Stripe key', 'stripe.com', '', true],
  ])
})

test('2fa.directory: a product subdomain entry covers the whole registrable domain', () => {
  const set = tfaDomains([['Gmail', { domain: 'mail.google.com', 'additional-domains': ['gmail.com'] }], ['Atlassian Cloud', { domain: 'id.atlassian.com' }]])
  assert.ok(supportsTfa(domainOf('https://accounts.google.com/signin'), set))
  assert.ok(supportsTfa(domainOf('https://acme.atlassian.com'), set))
  assert.ok(!supportsTfa('apple.com', set))
})

test('bundled 2FA list only names services that are in the live TOTP dataset', () => {
  // Apple and the big US banks use SMS or their own prompts, not TOTP; flagging them would be a false "missing 2FA".
  for (const d of ['apple.com', 'chase.com', 'bankofamerica.com', 'wellsfargo.com', 'americanexpress.com']) assert.ok(!TFA_FALLBACK.includes(d), d)
})
