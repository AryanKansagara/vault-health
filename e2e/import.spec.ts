import { ACCOUNTS, bitwardenCsv, chooseExport, expect, file, healthScore, importExport, newVault, pux, stat, test, vaultCsv } from './support'

/** What the engine should find in ACCOUNTS (see support.ts for how each item was built). */
async function expectFindings(page: import('@playwright/test').Page) {
  expect(await stat(page, 'Breached')).toBe(1)      // the router, via the stubbed breach corpus
  expect(await stat(page, 'Reused')).toBe(2)        // the two social logins
  expect(await stat(page, 'Near-reused')).toBe(2)   // Willow-2024! / Willow-2025!
  expect(await stat(page, 'Weak')).toBe(1)          // abc123
  expect(await stat(page, '2FA not set')).toBe(1)   // tfa-site.example is in the stubbed 2fa.directory list
  await expect(page.getByText(/Breach check (was skipped|only partly ran)/)).toHaveCount(0)
}

test('imports a CSV, checks breaches and 2FA through the stubs, and scores the vault', async ({ page, net }) => {
  await newVault(page)
  await chooseExport(page, file('fixture-vault.csv', vaultCsv()))
  await expect(page.getByText('Ready', { exact: true })).toBeVisible()
  await expect(page.getByText(`Detected: Generic CSV · ${ACCOUNTS.length} rows · ${ACCOUNTS.length} logins usable`)).toBeVisible()
  await page.getByRole('button', { name: `Analyze ${ACCOUNTS.length} logins` }).click()
  await page.waitForURL(/\/overview$/)
  await expectFindings(page)
  expect(await healthScore(page)).toBeLessThan(85)

  const hibp = net.requests.filter(r => r.url.startsWith('https://api.pwnedpasswords.com/'))
  expect(hibp.length).toBeGreaterThan(0)
  expect(net.requests.some(r => r.url === 'https://api.2fa.directory/v3/totp.json')).toBe(true)
  await expect(page.locator('.held')).toContainText('fixture-vault.csv')
})

test('imports a Bitwarden CSV and detects the format', async ({ page }) => {
  await newVault(page)
  await chooseExport(page, file('bw.csv', bitwardenCsv()))
  await expect(page.getByText(/Detected: Bitwarden \(CSV\)/)).toBeVisible()
  await page.getByRole('button', { name: /^Analyze 8 logins$/ }).click()
  await page.waitForURL(/\/overview$/)
  expect(await stat(page, 'Breached')).toBe(1)
  expect(await stat(page, 'Reused')).toBe(2)
})

test('imports a 1PUX archive with the same findings as the CSV', async ({ page }) => {
  await newVault(page)
  await chooseExport(page, file('fixture.1pux', pux(), 'application/zip'))
  await expect(page.getByText(/Detected: 1Password \(1PUX\)/)).toBeVisible()
  await page.getByRole('button', { name: `Analyze ${ACCOUNTS.length} logins` }).click()
  await page.waitForURL(/\/overview$/)
  await expectFindings(page)
})

test('"Clear from memory" drops the imported file and keeps the findings', async ({ page }) => {
  await newVault(page)
  await importExport(page, file('fixture-vault.csv', vaultCsv()))
  const score = await healthScore(page)
  await page.getByRole('button', { name: 'Clear from memory' }).click()
  await expect(page.locator('.held')).toHaveCount(0)
  expect(await healthScore(page)).toBe(score)
})

test('unrelated passwords are not falsely grouped as near-reused', async ({ page }) => {
  await newVault(page)
  const unrelatedCsv = 'title,url,username,password\n' +
    'A,https://a.example,u1,x7!k9?m2&p\n' +
    'B,https://b.example,u2,x1%k8#m4*p\n' +
    'C,https://c.example,u3,7a91-2b48-6c30-5d82\n' +
    'D,https://d.example,u4,9a01-3b77-8c22-4d99\n' +
    'E,https://e.example,u5,test-404-err\n' +
    'F,https://f.example,u6,test-aoa-err\n' +
    'G,https://g.example,u7,pass-1-word\n' +
    'H,https://h.example,u8,password-2024\n'
  await importExport(page, file('unrelated.csv', unrelatedCsv))
  expect(await stat(page, 'Near-reused')).toBe(0)
})
