import { createHash } from 'node:crypto'
import { BREACHED_PW, ACCOUNTS, expect, file, importExport, newVault, stat, test, vaultCsv, healthScore } from './support'

const sha1 = (s: string) => createHash('sha1').update(s).digest('hex').toUpperCase()

async function itemsTab(page: import('@playwright/test').Page) {
  await page.getByRole('link', { name: 'Items' }).click()
  await expect(page.getByRole('heading', { name: /./ }).first()).toBeVisible()
}

for (const mode of ['http500', 'offline'] as const) {
  test(`a failed breach lookup (${mode}) is reported as unchecked, never as "not breached"`, async ({ page, net }) => {
    net.breach = mode
    await newVault(page)
    await importExport(page, file('fixture-vault.csv', vaultCsv()))

    await expect(page.getByText('Breach check was skipped; re-import online to complete it.')).toBeVisible()
    expect(await stat(page, 'Breached')).toBe(0)

    await itemsTab(page)
    const rows = page.locator('tbody tr')
    await expect(rows).toHaveCount(ACCOUNTS.length)
    // Every item says "unchecked"; none claims to be breached.
    await expect(rows.locator('.flag', { hasText: 'unchecked' })).toHaveCount(ACCOUNTS.length)
    await expect(rows.locator('.flag.bad', { hasText: 'breached' })).toHaveCount(0)
    // The unchecked router is not presented as clean either.
    await expect(rows.filter({ hasText: 'Fixture Router' }).locator('.flag', { hasText: 'unchecked' })).toBeVisible()
  })
}

test('a partly failed lookup flags only the unreachable items as unchecked', async ({ page, net }) => {
  // Fail the lookup for the one prefix that belongs to the breached router; the rest succeed.
  net.breach = { failPrefixes: [sha1(BREACHED_PW).slice(0, 5)] }
  await newVault(page)
  await importExport(page, file('fixture-vault.csv', vaultCsv()))

  await expect(page.getByText('Breach check only partly ran; re-import online to complete it.')).toBeVisible()
  expect(await stat(page, 'Breached')).toBe(0)
  await itemsTab(page)
  const rows = page.locator('tbody tr')
  await expect(rows.filter({ hasText: 'Fixture Router' }).locator('.flag', { hasText: 'unchecked' })).toBeVisible()
  await expect(rows.filter({ hasText: 'Fixture Wiki' }).locator('.flag', { hasText: 'unchecked' })).toHaveCount(0)
  await expect(rows.locator('.flag', { hasText: 'unchecked' })).toHaveCount(1)
})

test('when the lookup works the breached router is flagged and the score reflects it', async ({ page, net }) => {
  await newVault(page)
  await importExport(page, file('fixture-vault.csv', vaultCsv()))
  const withBreach = await healthScore(page)
  expect(await stat(page, 'Breached')).toBe(1)
  await itemsTab(page)
  await expect(page.locator('tbody tr', { hasText: 'Fixture Router' }).locator('.flag.bad', { hasText: 'breached' })).toBeVisible()

  // The same vault with an empty breach corpus scores better, so the breach really drives the score.
  net.breachedPasswords.clear()
  await page.getByRole('link', { name: 'Import' }).click()
  await importExport(page, file('fixture-vault.csv', vaultCsv()))
  expect(await stat(page, 'Breached')).toBe(0)
  expect(await healthScore(page)).toBeGreaterThan(withBreach)
})
