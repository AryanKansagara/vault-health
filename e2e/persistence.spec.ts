import { expect, file, importExport, newVault, healthScore, test, vaultCsv } from './support'

test('settings and theme persist across a reload', async ({ page }) => {
  await page.goto('/settings')
  await page.getByLabel(/Clear the imported file from memory/).check()
  await page.getByRole('radio', { name: 'Dark' }).click()
  await expect(page.locator('html')).toHaveAttribute('data-theme-mode', 'dark')

  await page.reload()
  await expect(page.getByLabel(/Clear the imported file from memory/)).toBeChecked()
  await expect(page.getByLabel(/Check passwords against Have I Been Pwned/)).toBeChecked()
  await expect(page.locator('html')).toHaveAttribute('data-theme-mode', 'dark')
  await expect(page.getByRole('radio', { name: 'Dark' })).toHaveAttribute('aria-checked', 'true')
})

test('an imported vault, its snapshot and a rotation mark are kept after a reload', async ({ page }) => {
  const id = await newVault(page)
  await importExport(page, file('fixture-vault.csv', vaultCsv()))
  const score = await healthScore(page)

  await page.getByRole('button', { name: 'Save snapshot' }).click()
  await expect(page.getByText('Snapshot saved')).toBeVisible()
  await page.getByRole('button', { name: 'Rotated' }).first().click()
  await expect(page.getByText(/Marked \d+ items? as rotated/)).toBeVisible()
  const after = await healthScore(page)
  expect(after).toBeGreaterThan(score)

  await page.reload()
  await page.waitForURL(`**/app/p/${id}/overview`)
  await expect.poll(() => healthScore(page)).toBe(after)
  // The imported file itself is gone after a reload, since it was only ever held in memory.
  await expect(page.locator('.held')).toHaveCount(0)

  // One snapshot from the import and one saved by hand.
  await page.getByRole('link', { name: 'History' }).click()
  await expect(page.locator('.snap-list li')).toHaveCount(2)
})

test('with "clear from memory" on, the file is released as soon as analysis ends', async ({ page }) => {
  await page.goto('/settings')
  await page.getByLabel(/Clear the imported file from memory/).check()
  await newVault(page)
  await importExport(page, file('fixture-vault.csv', vaultCsv()))
  await expect(page.locator('.held')).toHaveCount(0)
})
