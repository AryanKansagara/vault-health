import { SECRETS, chooseExport, dumpStorage, expect, expectNoSecrets, file, newVault, test, vaultCsv, zip } from './support'

// Layout of Bitwarden's password-protected encrypted JSON export, with fake values:
// github.com/bitwarden/clients, libs/importer/src/importers/spec-data/bitwarden-json/password-protected.json.ts
const encryptedBitwarden = JSON.stringify({
  encrypted: true, passwordProtected: true, salt: 'ZmFrZS1zYWx0', kdfIterations: 100000, kdfType: 0,
  encKeyValidation_DO_NOT_EDIT: '2.ZmFrZQ==|ZmFrZQ==|ZmFrZQ==', data: '2.ZmFrZQ==|ZmFrZQ==|ZmFrZQ==',
})
const full = vaultCsv()

const cases: { name: string; file: ReturnType<typeof file>; message: RegExp; /** Rejected before the validation report (a banner), or inside it. */ where: 'banner' | 'report' }[] = [
  { name: 'empty file', file: file('empty.csv', ''), message: /The file is empty/, where: 'report' },
  { name: 'header only', file: file('header-only.csv', 'vault,title,url,username,password\n'), message: /No logins with passwords were found/, where: 'report' },
  { name: 'no password column', file: file('no-password.csv', 'site,login\nexample.test,zq.user\n'), message: /No password column found\. Columns seen: site, login/, where: 'report' },
  { name: 'binary junk', file: file('junk.csv', Buffer.from([0x00, 0xff, 0xfe, 0x41, 0x00, 0x42, 0x00]), 'application/octet-stream'), message: /No password column found/, where: 'report' },
  { name: 'every data row cut off', file: file('cut.csv', full.slice(0, full.indexOf('\n') + 12)), message: /Only 1 column\(s\); skipped|No logins with passwords were found/, where: 'report' },
  { name: 'encrypted Bitwarden JSON', file: file('encrypted.json', encryptedBitwarden, 'application/json'), message: /JSON exports are not supported yet\. Export as CSV instead/, where: 'banner' },
  { name: 'truncated zip', file: file('cut.1pux', zip('export.data', '{"accounts":[]}').subarray(0, 40), 'application/zip'), message: /Not a zip archive/, where: 'banner' },
  { name: 'zip without export.data', file: file('other.1pux', zip('notes.txt', 'hello'), 'application/zip'), message: /no export\.data inside/, where: 'banner' },
  { name: '1PUX with no accounts', file: file('empty.1pux', zip('export.data', '{"accounts":[]}'), 'application/zip'), message: /No login items with passwords were found/, where: 'report' },
]

for (const c of cases) {
  test(`${c.name}: a clear message, nothing to analyze, no health score`, async ({ page }) => {
    await newVault(page)
    await chooseExport(page, c.file)
    await expect(page.getByText(c.message).first()).toBeVisible()
    if (c.where === 'report') await expect(page.getByText('Cannot import', { exact: true })).toBeVisible()
    await expect(page.getByRole('alert').or(page.locator('.validation'))).toBeVisible()
    // Nothing can be analyzed, so no score can be produced.
    const analyze = page.getByRole('button', { name: /^Analyze/ })
    if (await analyze.count()) await expect(analyze).toBeDisabled()
    await expect(page.getByRole('img', { name: /Vault health/ })).toHaveCount(0)

    // The vault stays empty: no findings, no score on the vault list, no secrets stored.
    await page.goto('/app')
    const card = page.locator('.project-card')
    await expect(card).toContainText('No import yet')
    await expect(card.locator('.score-chip')).toHaveCount(0)
    expectNoSecrets(await dumpStorage(page), 'browser storage')
    expect(SECRETS.length).toBeGreaterThan(0)
  })
}

test('a CSV cut off mid-file imports only the complete rows and says which row was lost', async ({ page }) => {
  await newVault(page)
  await chooseExport(page, file('cut.csv', full.slice(0, full.indexOf('Fixture Router') + 40)))
  await expect(page.getByText('Ready', { exact: true })).toBeVisible()
  await expect(page.getByText('Detected: Generic CSV · 4 rows · 3 logins usable')).toBeVisible()
  await expect(page.getByText(/line 5.*Has 3 of 7 columns; skipped/i)).toBeVisible()
  await expect(page.getByRole('button', { name: 'Analyze 3 logins' })).toBeEnabled()
})

test('discarding a validated export leaves nothing behind', async ({ page }) => {
  await newVault(page)
  await chooseExport(page, file('fixture-vault.csv', full))
  await page.getByRole('button', { name: 'Discard' }).click()
  await expect(page.locator('.validation')).toHaveCount(0)
  await page.goto('/app')
  await expect(page.locator('.project-card')).toContainText('No import yet')
  expectNoSecrets(await dumpStorage(page), 'browser storage')
})
