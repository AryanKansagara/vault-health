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

test('unchecked or partial breach results never show "0 breached" or "Healthy" across cards, report, attestation, CSV or history', async ({ page, net }) => {
  const { readFile } = await import('node:fs/promises')
  const strongUncheckedCsv = 'title,url,username,password,last_changed\nOne,https://one.example,u1,k7#Rm2$vQp9!wLx4Tz8@nB5c,2026-10-01\nTwo,https://two.example,u2,m9!Xp4#sTr7@qWz2Kv6$yH8d,2026-10-01\n'

  // 1) Full breach failure on a strong vault that would otherwise score ~100.
  net.breach = 'http500'
  const id = await newVault(page)
  await importExport(page, file('strong.csv', strongUncheckedCsv))
  await expect(page.getByRole('img', { name: /Vault health: \d+ out of 100/ })).toContainText('Provisional')
  await expect(page.locator('.ring-panel')).not.toContainText('Healthy')
  await expect(page.locator('.stat-grid')).toContainText('Breached (not checked)')
  await expect(page.locator('.stat-grid')).toContainText('Unchecked')

  // Card
  await page.goto('/app')
  await expect(page.locator('.project-card')).toContainText('Provisional')
  await expect(page.locator('.project-card')).toContainText('breach check not run')
  await expect(page.locator('.project-card')).not.toContainText(/0 breached|Healthy/i)

  // Fix plan & CSV (enabled even when risk=0 because items are unchecked)
  await page.goto(`/app/p/${id}/actions`)
  await expect(page.getByText(/Breach check incomplete/).first()).toBeVisible()
  const [dl] = await Promise.all([page.waitForEvent('download'), page.getByRole('button', { name: 'Download CSV' }).click()])
  const csvText = await readFile((await dl.path())!, 'utf8')
  expect(csvText).toContain('unchecked')
  expect(csvText).toContain('Breach status unchecked')

  // Report & Attestation
  await page.goto(`/app/p/${id}/report`)
  await expect(page.locator('.report')).toContainText(/Provisional/i)
  await expect(page.locator('.report')).toContainText('The breach check did not run')
  await expect(page.locator('.report')).not.toContainText(/Healthy|0 items use a password found in public breaches/i)
  await page.goto(`/app/p/${id}/attest`)
  await expect(page.locator('.report')).toContainText('breach check not run')
  await expect(page.locator('.report')).toContainText(/provisional/i)
  await expect(page.locator('.report')).not.toContainText(/0 breached|Healthy/i)

  // 2) Partial failure as a second snapshot -> History compare & Trend
  net.breach = { failPrefixes: [sha1('k7#Rm2$vQp9!wLx4Tz8@nB5c').slice(0, 5)] }
  await page.goto(`/app/p/${id}/import`)
  await importExport(page, file('strong.csv', strongUncheckedCsv))
  await page.goto(`/app/p/${id}/history`)
  await expect(page.locator('.snap-list')).toContainText('breach check not run')
  await expect(page.locator('.snap-list')).toContainText('1 unchecked (breach check partial)')
  await expect(page.locator('.snap-list')).toContainText('(provisional)')
  await expect(page.locator('.diff-stats')).toContainText('breach check not run → 1 unchecked (breach check partial)')
  await expect(page.locator('.diff-stats')).not.toContainText(/\b0\s*→/)
  await expect(page.locator('svg.trend')).toHaveAttribute('aria-label', /\(provisional\)/)

  await page.goto('/app')
  await expect(page.locator('.project-card')).toContainText('1 unchecked (breach check partial)')
  await expect(page.locator('.project-card')).not.toContainText(/0 breached|Healthy/i)
})
