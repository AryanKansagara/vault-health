import { accessCsv, expect, file, importExport, newVault, test, vaultCsv } from './support'
import type { Page } from '@playwright/test'

async function vaultWithAccessList(page: Page) {
  const id = await newVault(page)
  await page.locator('input[type=file]').nth(1).setInputFiles(file('access.csv', accessCsv))
  await expect(page.getByText(/Current: 5 rows, 3 people, 2 vaults/)).toBeVisible()
  await importExport(page, file('fixture-vault.csv', vaultCsv()))
  await page.getByRole('link', { name: 'Offboarding' }).click()
  await page.getByLabel('Departing person', { exact: true }).selectOption('Fixture Leaver')
  return id
}

const progress = async (page: Page) => (await page.locator('.progress-box strong').textContent())!.trim()

test('offboarding a person lists what they could open, worst blast radius first', async ({ page }) => {
  await vaultWithAccessList(page)
  const steps = page.locator('.checklist li')
  // Fixture Leaver is in Marketing and Operations: the 7 items there. The reused social logins share one step and so
  // do the two near-identical billing passwords, which leaves 5 steps.
  const total = Number((await progress(page)).split('/')[1])
  expect(total).toBe(5)
  await expect(steps).toHaveCount(total)
  await expect(steps.first()).toContainText('Fixture Social A + 1 more')
  await expect(steps.first()).toContainText('Rotate together, same password on')
  await expect(steps.nth(1)).toContainText('Fixture Billing + 1 more')
  // Highest blast radius first.
  const blast = (await steps.locator('.step-meta').allInnerTexts()).map(t => Number(t.match(/Blast radius ([\d.]+)/)![1]))
  expect(blast).toEqual([...blast].sort((a, b) => b - a))
  // The private vault item is out of reach for them.
  await expect(page.locator('.checklist')).not.toContainText('Fixture Private Note Site')
})

test('the checklist and its progress survive a reload', async ({ page }) => {
  const id = await vaultWithAccessList(page)
  const total = Number((await progress(page)).split('/')[1])
  const first = page.locator('.checklist li').first()
  // The box is controlled and follows the save to IndexedDB, so click and then wait for it rather than using check().
  await first.getByRole('checkbox').click()
  await expect(first).toHaveClass(/done/)
  // The reused pair counts as one step but rotates both items.
  expect(await progress(page)).toBe(`1 / ${total}`)
  await expect(page.locator('.progress-box')).toContainText('Close plan')

  await page.reload()
  await page.waitForURL(`**/app/p/${id}/offboard`)
  await expect(page.locator('.checklist li').first().getByRole('checkbox')).toBeChecked()
  await expect(page.locator('.checklist li').first()).toHaveClass(/done/)
  expect(await progress(page)).toBe(`1 / ${total}`)
  await expect(page.getByLabel('Departing person', { exact: true })).toHaveValue('Fixture Leaver')

  // The rotation also shows on the Items tab and on the vault card.
  await page.getByRole('link', { name: 'Items' }).click()
  await expect(page.locator('tbody .flag.good', { hasText: /^rotated/ })).toHaveCount(2)
  await page.goto('/app')
  await expect(page.locator('.project-card')).toContainText('Offboarding plans1')
  await expect(page.locator('.project-card')).toContainText('Rotated2')
})

test('unticking a step is undone by the undo toast and the plan can be closed', async ({ page }) => {
  await vaultWithAccessList(page)
  const first = page.locator('.checklist li').first().getByRole('checkbox')
  await first.click()
  await expect(first).toBeChecked()
  await first.click()
  await expect(first).not.toBeChecked()
  await expect(page.getByText('Unticked')).toBeVisible()
  await page.getByRole('button', { name: 'Undo' }).click()
  await expect(first).toBeChecked()

  await page.getByRole('button', { name: 'Close plan' }).click()
  await page.getByRole('dialog', { name: 'Close the plan for Fixture Leaver?' }).getByRole('button', { name: 'Close plan' }).click()
  await expect(page.getByText('Plan closed')).toBeVisible()
  await expect(page.locator('.progress-box')).not.toContainText('Close plan')
  await expect(page.locator('.checklist li.done')).toHaveCount(0)
  await page.reload()
  await expect(page.getByLabel('Departing person', { exact: true })).toBeVisible()
  await expect(page.locator('.progress-box')).not.toContainText('Close plan')
})

test('without an access list a hand-tagged plan survives a reload', async ({ page }) => {
  const id = await newVault(page)
  await importExport(page, file('fixture-vault.csv', vaultCsv()))
  await page.getByRole('link', { name: 'Offboarding' }).click()
  await page.getByLabel('Departing person name').fill('Fixture Contractor')
  await page.getByRole('button', { name: 'Use' }).click()
  const tag = page.locator('.tag-grid').getByLabel(/Fixture Router/)
  await tag.click()
  await expect(tag).toBeChecked()
  await expect(page.locator('.checklist li')).toHaveCount(1)
  await page.locator('.checklist li').first().getByRole('checkbox').click()
  await expect(page.locator('.checklist li').first().getByRole('checkbox')).toBeChecked()

  await page.reload()
  await page.waitForURL(`**/app/p/${id}/offboard`)
  await expect(page.getByLabel('Departing person name')).toBeVisible()
  await expect(page.locator('.checklist li')).toHaveCount(1)
  await expect(page.locator('.checklist li').first().getByRole('checkbox')).toBeChecked()
})
