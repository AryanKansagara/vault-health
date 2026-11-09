import type { Finding } from './analyze.ts'
import { toCsv } from './csv.ts'
import type { Access } from './formats.ts'

/** Risk weights, in points out of 100 per item. Documented on /docs#scoring; change them here and nowhere else. */
export const WEIGHTS = {
  breached: 35,
  reusedBase: 20,
  reusedPerExtra: 2,
  reusedMax: 30,
  nearReuse: 12,
  strength: [20, 15, 7, 2, 0],
  olderThan1y: 7,
  olderThan2y: 12,
  missing2fa: 8,
  sharedVault: 8,
} as const

export type Severity = 'critical' | 'high' | 'medium' | 'low'
export const severity = (r: number): Severity => (r >= 50 ? 'critical' : r >= 25 ? 'high' : r >= 10 ? 'medium' : 'low')

export interface Ctx {
  now: Date
  groupSize: Map<string, number>
  nearSize: Map<string, number>
  /** Vault name -> number of people with access (from the access list). */
  members: Map<string, number>
}

export function context(fs: Finding[], access: Access[] = [], now = new Date()): Ctx {
  const groupSize = new Map<string, number>(), nearSize = new Map<string, number>()
  for (const f of fs) {
    if (f.group) groupSize.set(f.group, (groupSize.get(f.group) ?? 0) + 1)
    if (f.near) nearSize.set(f.near, (nearSize.get(f.near) ?? 0) + 1)
  }
  const sets = new Map<string, Set<string>>()
  for (const a of access) if (a.vault) (sets.get(a.vault) ?? sets.set(a.vault, new Set()).get(a.vault)!).add(a.person)
  return { now, groupSize, nearSize, members: new Map([...sets].map(([k, v]) => [k, v.size])) }
}

export const ageDays = (f: Finding, now: Date) => (f.changed ? Math.floor((now.getTime() - Date.parse(f.changed + 'T00:00:00Z')) / 864e5) : null)
export const isShared = (f: Finding, ctx: Ctx) => f.shared || (ctx.members.get(f.vault) ?? 0) > 1

export interface Reason { key: keyof typeof WEIGHTS | 'reused' | 'strength' | 'age'; points: number; text: string }

export function reasons(f: Finding, ctx: Ctx): Reason[] {
  const out: Reason[] = []
  if (f.breached) out.push({ key: 'breached', points: WEIGHTS.breached, text: 'Password appears in known breaches' })
  const g = f.group ? ctx.groupSize.get(f.group) ?? 1 : 1
  if (g > 1) out.push({ key: 'reused', points: Math.min(WEIGHTS.reusedMax, WEIGHTS.reusedBase + WEIGHTS.reusedPerExtra * (g - 2)), text: `Same password used on ${g} items` })
  else if (f.near && (ctx.nearSize.get(f.near) ?? 1) > 1) out.push({ key: 'nearReuse', points: WEIGHTS.nearReuse, text: `Variant of a password used on ${ctx.nearSize.get(f.near)! - 1} other item${ctx.nearSize.get(f.near)! > 2 ? 's' : ''}` })
  const sp = WEIGHTS.strength[Math.max(0, Math.min(4, f.strength))]
  if (sp) out.push({ key: 'strength', points: sp, text: ['Very weak password', 'Weak password', 'Fair password', 'Good, not great'][f.strength] })
  const age = ageDays(f, ctx.now)
  if (age !== null && age > 730) out.push({ key: 'age', points: WEIGHTS.olderThan2y, text: `Not changed in ${Math.floor(age / 365)} years` })
  else if (age !== null && age > 365) out.push({ key: 'age', points: WEIGHTS.olderThan1y, text: 'Not changed in over a year' })
  if (f.tfa && !f.totp) out.push({ key: 'missing2fa', points: WEIGHTS.missing2fa, text: 'Site supports 2FA but no TOTP is saved' })
  if (isShared(f, ctx)) out.push({ key: 'sharedVault', points: WEIGHTS.sharedVault, text: (ctx.members.get(f.vault) ?? 0) > 1 ? `Shared with ${ctx.members.get(f.vault)} people` : 'Lives in a shared vault' })
  return out
}

export const risk = (f: Finding, ctx: Ctx) => Math.min(100, reasons(f, ctx).reduce((a, r) => a + r.points, 0))

export interface Summary {
  health: number
  n: number
  meanRisk: number
  bySeverity: Record<Severity, number>
  breached: number
  reused: number
  near: number
  weak: number
  old: number
  missing2fa: number
  shared: number
  unchecked: number
}

/**
 * Overall health, 0-100: 100 − (½ × mean item risk + ½ × % of items rated high or critical).
 * The second half keeps a few dangerous items from hiding inside a large, mostly-clean vault.
 */
export function summarize(fs: Finding[], ctx: Ctx): Summary {
  const s: Summary = { health: 100, n: fs.length, meanRisk: 0, bySeverity: { critical: 0, high: 0, medium: 0, low: 0 }, breached: 0, reused: 0, near: 0, weak: 0, old: 0, missing2fa: 0, shared: 0, unchecked: 0 }
  if (!fs.length) return s
  let total = 0
  for (const f of fs) {
    const r = risk(f, ctx)
    total += r
    s.bySeverity[severity(r)]++
    if (f.breached) s.breached++
    if (f.breached === null) s.unchecked++
    if (f.group && (ctx.groupSize.get(f.group) ?? 0) > 1) s.reused++
    else if (f.near && (ctx.nearSize.get(f.near) ?? 0) > 1) s.near++
    if (f.strength <= 1) s.weak++
    if ((ageDays(f, ctx.now) ?? 0) > 365) s.old++
    if (f.tfa && !f.totp) s.missing2fa++
    if (isShared(f, ctx)) s.shared++
  }
  s.meanRisk = total / fs.length
  const badShare = (s.bySeverity.critical + s.bySeverity.high) / fs.length
  s.health = Math.max(0, Math.min(100, Math.round(100 - 0.5 * s.meanRisk - 50 * badShare)))
  return s
}

/** What an item looks like once its password is rotated to a fresh generated one today. */
export function rotated(f: Finding, today: string): Finding {
  return { ...f, strength: 4, group: null, near: null, breached: false, changed: today }
}

/** Applies the user's "rotated" marks (finding id -> ISO date). */
export function applyFixes(fs: Finding[], fixed: Record<string, string>): Finding[] {
  return fs.map(f => (fixed[f.id] && (!f.changed || fixed[f.id] >= f.changed) ? rotated(f, fixed[f.id]) : f))
}

/** Items that must rotate together with f: same or near-same password. */
export function siblings(f: Finding, fs: Finding[]): Finding[] {
  return fs.filter(x => x.id !== f.id && ((f.group && x.group === f.group) || (f.near && x.near === f.near)))
}

// ---------- Offboarding ----------

export interface Step {
  finding: Finding
  risk: number
  /** People who keep access and must be told about the new password. */
  audience: number
  blast: number
  owner: string
  also: Finding[]
  why: string[]
}

/** Everything the person could open: vaults they belong to, items granted directly, plus manual tags. */
export function reachable(person: string, fs: Finding[], access: Access[], tags: string[] = []): Finding[] {
  const mine = access.filter(a => a.person === person)
  const vaults = new Set(mine.filter(a => a.vault && !a.item).map(a => a.vault))
  const items = new Set(mine.filter(a => a.item).map(a => a.item.toLowerCase()))
  const tagged = new Set(tags)
  return fs.filter(f => vaults.has(f.vault) || items.has(f.title.toLowerCase()) || tagged.has(f.id))
}

export const people = (access: Access[]) => [...new Set(access.map(a => a.person))].sort((a, b) => a.localeCompare(b))

/**
 * Rotation checklist for a departing person, ordered by blast radius:
 * blast = 10 × accounts that open with this password (the item plus its reuse siblings) + people who must get the new password (capped at 10) + risk / 10.
 */
export function offboard(person: string, fs: Finding[], access: Access[], ctx: Ctx, tags: string[] = []): Step[] {
  const steps = reachable(person, fs, access, tags).map(f => {
    const others = access.filter(a => a.person !== person && (a.vault === f.vault || a.item.toLowerCase() === f.title.toLowerCase()))
    const audience = new Set(others.map(a => a.person)).size
    const owner = others.find(a => a.role === 'owner')?.person ?? others[0]?.person ?? 'Unassigned'
    const also = siblings(f, fs)
    const r = risk(f, ctx)
    const why = [
      `${person} could read it`,
      ...(audience ? [`${audience} other ${audience === 1 ? 'person' : 'people'} use it`] : []),
      ...(also.length ? [`password shared with ${also.length} other item${also.length > 1 ? 's' : ''}`] : []),
      ...(f.breached ? ['already breached'] : []),
    ]
    return { finding: f, risk: r, audience, blast: Math.round(((1 + also.length) * 10 + Math.min(audience, 10) + r / 10) * 10) / 10, owner, also, why }
  })
  return steps.sort((a, b) => b.blast - a.blast || b.risk - a.risk || a.finding.title.localeCompare(b.finding.title))
}

// ---------- Snapshots ----------

export interface Snapshot {
  id: string
  label: string
  at: string
  summary: Summary
  risks: Record<string, number>
  titles: Record<string, string>
}

export function snapshot(fs: Finding[], ctx: Ctx, id: string, label: string): Snapshot {
  const risks: Record<string, number> = {}, titles: Record<string, string> = {}
  for (const f of fs) { risks[f.id] = risk(f, ctx); titles[f.id] = f.title }
  return { id, label, at: ctx.now.toISOString(), summary: summarize(fs, ctx), risks, titles }
}

export interface Diff { healthDelta: number; fixed: string[]; worse: string[]; added: string[]; removed: string[] }

/** Fixed = was high or critical (risk ≥ 25) and is now below that, or the item is gone. */
export function compare(a: Snapshot, b: Snapshot): Diff {
  const d: Diff = { healthDelta: b.summary.health - a.summary.health, fixed: [], worse: [], added: [], removed: [] }
  for (const [id, r] of Object.entries(a.risks)) {
    const nr = b.risks[id]
    if (nr === undefined) { d.removed.push(id); if (r >= 25) d.fixed.push(id) }
    else if (r >= 25 && nr < 25) d.fixed.push(id)
    else if (severity(nr) !== severity(r) && nr > r) d.worse.push(id)
  }
  for (const id of Object.keys(b.risks)) if (a.risks[id] === undefined) d.added.push(id)
  return d
}

// ---------- Fix plan ----------

export function action(f: Finding, ctx: Ctx): string {
  const parts: string[] = []
  const reused = siblingsCount(f, ctx)
  if (f.breached || reused || f.strength <= 2 || (ageDays(f, ctx.now) ?? 0) > 365) parts.push('Rotate to a generated 20+ character password')
  if (reused) parts.push(`then rotate the ${reused} other item${reused > 1 ? 's' : ''} that share it`)
  if (f.tfa && !f.totp) parts.push('turn on 2FA and save the TOTP in the vault')
  if (f.sso && isShared(f, ctx)) parts.push('consider moving it behind SSO')
  return parts.length ? parts.join('; ').replace(/^./, c => c.toUpperCase()) : 'No action needed'
}
const siblingsCount = (f: Finding, ctx: Ctx) => (f.group ? (ctx.groupSize.get(f.group) ?? 1) - 1 : f.near ? (ctx.nearSize.get(f.near) ?? 1) - 1 : 0)

export function prioritized(fs: Finding[], ctx: Ctx) {
  return fs.map(f => ({ f, r: risk(f, ctx) })).filter(x => x.r > 0).sort((a, b) => b.r - a.r || a.f.title.localeCompare(b.f.title))
}

export function fixPlanCsv(fs: Finding[], ctx: Ctx): string {
  const rows: (string | number | boolean | null)[][] = [['priority', 'item', 'domain', 'vault', 'risk', 'severity', 'breached', 'reused_with', 'strength_0_4', 'last_changed', 'two_factor_available', 'totp_saved', 'shared', 'sso_candidate', 'action', 'reasons']]
  prioritized(fs, ctx).forEach(({ f, r }, i) => rows.push([i + 1, f.title, f.domain, f.vault, r, severity(r), f.breached ?? 'unchecked', siblingsCount(f, ctx), f.strength, f.changed, f.tfa, f.totp, isShared(f, ctx), f.sso, action(f, ctx), reasons(f, ctx).map(x => x.text).join('; ')]))
  return toCsv(rows)
}
