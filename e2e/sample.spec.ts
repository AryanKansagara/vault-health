import { expect, healthScore, test } from './support'

test('opens a synthetic sample, shows the score and a fix plan', async ({ page }) => {
  await page.goto('/app')
  await page.getByRole('button', { name: /Northwind Creative/ }).click()
  await page.waitForURL(/\/app\/p\/[\w-]+$/)

  await expect(page.getByRole('heading', { level: 1, name: /Northwind Creative/ })).toBeVisible()
  await expect(page.getByText('Synthetic', { exact: true }).first()).toBeVisible()
  const score = await healthScore(page)
  expect(score).toBeGreaterThan(0)
  expect(score).toBeLessThan(100)
  // The overview names the worst items first and lets you mark them rotated.
  await expect(page.getByRole('heading', { name: 'Fix first' })).toBeVisible()
  expect(await page.locator('.fix-list li').count()).toBeGreaterThan(0)

  await page.getByRole('link', { name: 'Fix plan' }).click()
  await expect(page.getByRole('heading', { name: 'Prioritized fixes' })).toBeVisible()
  const plan = page.locator('.plan-list li')
  expect(await plan.count()).toBeGreaterThan(0)
  await expect(plan.first()).toContainText(/\S/)
})

test('a sample opened by URL lands on the requested tab', async ({ page }) => {
  await page.goto('/app?sample=dental&tab=actions')
  await page.waitForURL(/\/app\/p\/[\w-]+\/actions$/)
  await expect(page.getByRole('heading', { name: 'Fix plan (CSV)' })).toBeVisible()
})

test('the sample and its score are still there after a reload', async ({ page }) => {
  await page.goto('/app?sample=freight')
  await page.waitForURL(/\/app\/p\/[\w-]+$/)
  const before = await healthScore(page)
  const url = page.url()

  await page.reload()
  await expect(page.getByRole('heading', { level: 1, name: /Ridgeline Freight/ })).toBeVisible()
  expect(await healthScore(page)).toBe(before)

  // The vault list remembers it too, with the same score.
  await page.goto('/app')
  const card = page.locator('.project-card', { hasText: 'Ridgeline Freight' })
  await expect(card.locator('.score-chip')).toHaveText(String(before))
  await card.getByRole('link', { name: 'Ridgeline Freight' }).click()
  await expect(page).toHaveURL(url)
})
