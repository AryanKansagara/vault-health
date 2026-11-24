import { createHash } from 'node:crypto'
import { readFile } from 'node:fs/promises'
import { ACCOUNTS, SECRETS, accessCsv, dumpStorage, expect, expectNoSecrets, file, importExport, newVault, pux, test, vaultCsv, type Net } from './support'
import type { Page } from '@playwright/test'

const sha1 = (s: string) => createHash('sha1').update(s).digest('hex').toUpperCase()

/** Reads a download the page triggers and returns its text. */
async function downloaded(page: Page, click: () => Promise<void>) {
  const [d] = await Promise.all([page.waitForEvent('download'), click()])
  return { name: d.suggestedFilename(), text: await readFile((await d.path())!, 'utf8') }
}

function expectNothingLeftTheBrowser(net: Net) {
  for (const r of net.requests) {
    const wire = `${r.url}\n${JSON.stringify(r.headers)}\n${r.body}`
    expectNoSecrets(wire, `request ${r.method} ${r.url}`)
  }
  // The breach lookup is k-anonymity only: a 5-character hash prefix in the path, nothing else.
  const hibp = net.requests.filter(r => new URL(r.url).hostname === 'api.pwnedpasswords.com')
  expect(hibp.length).toBeGreaterThan(0)
  for (const r of hibp) {
    expect(r.method).toBe('GET')
    expect(new URL(r.url).pathname).toMatch(/^\/range\/[0-9A-F]{5}$/)
    expect(new URL(r.url).search).toBe('')
    expect(r.body).toBe('')
    expect(r.headers['add-padding']).toBe('true')
  }
  // Every prefix asked for belongs to one of the fixture passwords, and each password is covered.
  const asked = new Set(hibp.map(r => new URL(r.url).pathname.slice(-5)))
  for (const a of ACCOUNTS) expect(asked, `no breach lookup for ${a.title}`).toContain(sha1(a.password).slice(0, 5))
  // Nothing but the app itself, the two stubbed services and (blocked) fonts was contacted.
  const hosts = new Set(net.requests.map(r => new URL(r.url).hostname))
  expect([...hosts].filter(h => h !== '127.0.0.1' && !/^fonts\.(googleapis|gstatic)\.com$/.test(h)).sort()).toEqual(['api.2fa.directory', 'api.pwnedpasswords.com'])
}

for (const [label, f] of [['CSV', () => file('fixture-vault.csv', vaultCsv())], ['1PUX', () => file('fixture.1pux', pux(), 'application/zip')]] as const) {
  test(`after a ${label} import no password or username is stored, downloaded or sent`, async ({ page, net }) => {
    await newVault(page)
    await page.locator('input[type=file]').nth(1).setInputFiles(file('access.csv', accessCsv))
    await expect(page.getByText(/Current: 5 rows/)).toBeVisible()
    await importExport(page, f())

    // Storage: the scan is only meaningful if the findings really are in there.
    const stored = await dumpStorage(page)
    expect(stored).toContain('Fixture Router')
    expect(stored).toContain('Fixture Leaver')
    expectNoSecrets(stored, 'browser storage')
    expect(JSON.parse(stored).databases).toEqual(['vault-health'])

    // Downloads: the fix-plan CSV and the full JSON export.
    await page.getByRole('link', { name: 'Fix plan' }).click()
    const plan = await downloaded(page, () => page.getByRole('button', { name: 'Download CSV' }).click())
    expect(plan.name).toMatch(/fix-plan-\d{4}-\d{2}-\d{2}\.csv$/)
    expect(plan.text).toContain('Fixture Router')
    expectNoSecrets(plan.text, 'the fix-plan CSV')

    await page.goto('/settings')
    const all = await downloaded(page, () => page.getByRole('button', { name: 'Export all my data (JSON)' }).click())
    expect(all.name).toMatch(/^vault-health-export-.*\.json$/)
    expect(all.text).toContain('Fixture Router')
    expect(() => JSON.parse(all.text)).not.toThrow()
    expectNoSecrets(all.text, 'the JSON export')

    // The printable report is plain page text.
    await page.goto(`${new URL(page.url()).origin}/app`)
    await page.locator('.project-card h3 a').click()
    await page.getByRole('link', { name: 'Printable report' }).click()
    await expect(page.getByText('Fixture Router').first()).toBeVisible()
    expectNoSecrets(await page.locator('body').innerText(), 'the printable report')

    // After a reload the stored state is still free of secrets.
    await page.reload()
    expectNoSecrets(await dumpStorage(page), 'browser storage after reload')
    expectNothingLeftTheBrowser(net)
  })
}

test('with the breach check switched off nothing is sent to Have I Been Pwned', async ({ page, net }) => {
  await page.goto('/settings')
  await page.getByLabel(/Check passwords against Have I Been Pwned/).uncheck()
  await newVault(page)
  await importExport(page, file('fixture-vault.csv', vaultCsv()))
  expect(net.requests.filter(r => new URL(r.url).hostname === 'api.pwnedpasswords.com')).toEqual([])
  await expect(page.getByText('Breach check was skipped; re-import online to complete it.')).toBeVisible()
  expectNoSecrets(await dumpStorage(page), 'browser storage')
  expect(SECRETS.length).toBeGreaterThan(0)
})
