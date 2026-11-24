import { dumpStorage, chooseExport, expect, file, importExport, newVault, stat, test, zip } from './support'

// App bugs found while writing this suite. They are filed, not fixed here (the CI/E2E change touches nothing under src/).
// Each test states the behaviour the issue asks for and is marked test.fail(): it passes while the bug exists and starts
// failing once the bug is fixed, which is the cue to delete the test.fail() line and keep the test as a regression test.

test('#2 a username is not stored as the title of an untitled item', async ({ page }) => {
  test.fail()
  await newVault(page)
  await importExport(page, file('repro.csv', 'title,url,username,password\n,,zq.leaky.user@fixture.example,Zq-Leak-Pw-90817-Kd\nOk,https://ok.example,zq.other@fixture.example,Zq-Other-Pw-1234-Ab\n'))
  const stored = await dumpStorage(page)
  expect(stored).not.toContain('zq.leaky.user@fixture.example')
  expect(stored).not.toContain('zq.other@fixture.example')
})

test('#3 a CSV cut off in the middle of its last row is flagged', async ({ page }) => {
  test.fail()
  await newVault(page)
  await chooseExport(page, file('truncated.csv', 'vault,title,url,username,password,totp,last_changed\nOps,A,https://a.example,zq.a,Zq-Full-Password-1,,2026-01-01\nOps,B,https://b.example,zq.b,Zq-Truncated-Pass'))
  await expect(page.getByText('Ready', { exact: true })).toBeVisible()
  await expect(page.locator('.validation .issues li')).toHaveCount(1)
})

test('#4 a cut-off JSON export gets a message about the file, not a JSON.parse error', async ({ page }) => {
  test.fail()
  await newVault(page)
  await chooseExport(page, file('cut.json', '{"accounts":[{"vaults":[{"items":[{"overview":{"title":"x', 'application/json'))
  await expect(page.getByRole('alert')).toBeVisible()
  await expect(page.getByRole('alert')).not.toContainText(/JSON at position|Unexpected end of JSON/)
  await chooseExport(page, file('cut.1pux', zip('export.data', '{"accounts":[{"vaults":[{"items":[{"overview":{"title":"x'), 'application/zip'))
  await expect(page.getByRole('alert')).not.toContainText(/JSON at position|Unexpected end of JSON/)
})

test('#5 the vault list does not say "0 breached" after the breach check failed', async ({ page, net }) => {
  test.fail()
  net.breach = 'http500'
  await newVault(page)
  await importExport(page, file('repro.csv', 'title,url,username,password\nRouter,http://router.example,zq.admin,Zq-Fixture-Breached-0001\nWiki,https://wiki.example,zq.wiki,abc123\n'))
  await page.goto('/app')
  await expect(page.locator('.project-card')).not.toContainText('0 breached')
})

test('#6 near-identical passwords are grouped when the changing digits are in the middle', async ({ page }) => {
  test.fail()
  await newVault(page)
  await importExport(page, file('repro.csv', 'title,url,username,password\nA,https://a.example,u1,Zq-Willow-2024-Seed-Xk\nB,https://b.example,u2,Zq-Willow-2025-Seed-Xk\nC,https://c.example,u3,Zq-Willow-2024!\nD,https://d.example,u4,Zq-Willow-2025!\n'))
  expect(await stat(page, 'Near-reused')).toBe(4)
})
