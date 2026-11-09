import { useMemo } from 'react'
import { analyze, quickScore, type Finding } from './engine/analyze.ts'
import { TFA_FALLBACK } from './engine/domain.ts'
import { parseAccess, parseExport, type Access, type ParseResult } from './engine/formats.ts'
import { applyFixes, context, snapshot, summarize, type Ctx, type Summary } from './engine/risk.ts'
import { SAMPLES, sampleBreaches, sampleFiles } from './engine/sample.ts'
import { checkBreaches, strengthScorer, tfaSet } from './checks.ts'
import { blankProject, getPrefs, getProjects, saveProject, useProjects, uuid, type ImportMeta, type Project } from './store.ts'

export const today = () => new Date().toISOString().slice(0, 10)
const fmtLabel = (d: Date) => d.toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' })

/** Findings for a sample, computed by the same engine a real import uses (built-in strength estimator, bundled breach list). */
export async function sampleFindings(id: string, era: 'now' | 'before' = 'now'): Promise<{ findings: Finding[]; access: Access[] }> {
  const f = sampleFiles(id, era)
  const items = parseExport(f.vault).items
  const findings = await analyze(items, { score: quickScore, breached: await sampleBreaches(items), tfa: new Set(TFA_FALLBACK) })
  return { findings, access: parseAccess(f.access).rows }
}

export async function createSampleProject(sampleId: string): Promise<Project> {
  const existing = getProjects().find(p => p.sampleId === sampleId)
  if (existing) return existing
  const def = SAMPLES.find(s => s.id === sampleId)!
  const [now, before] = await Promise.all([sampleFindings(sampleId), sampleFindings(sampleId, 'before')])
  const then = new Date(Date.now() - 91 * 864e5)
  const p = blankProject(def.name)
  const at = Date.now()
  const meta = (kind: ImportMeta['kind'], n: number, items: number): ImportMeta => ({ id: uuid(), kind, format: 'synthetic', fileName: kind === 'vault' ? 'synthetic vault export' : 'synthetic access list', rows: n, items, warnings: 0, at, breach: 'sample', tfa: 'bundled', strength: 'built-in' })
  return saveProject({
    ...p,
    sampleId,
    findings: now.findings,
    access: now.access,
    imports: [meta('vault', now.findings.length, now.findings.length), meta('access', now.access.length, now.access.length)],
    snapshots: [
      snapshot(before.findings, context(before.findings, before.access, then), uuid(), `Quarterly review, ${fmtLabel(then)}`),
      snapshot(now.findings, context(now.findings, now.access), uuid(), `Import, ${fmtLabel(new Date())}`),
    ],
  })
}

export type Stage = 'parsing' | 'strength' | 'breach' | 'tfa' | 'saving'

/** Turns a parsed export into findings and saves them. The parsed items (with passwords) never leave this function except via the caller's memory hold. */
export async function importVault(p: Project, parsed: ParseResult, fileName: string, onStage: (s: Stage, detail?: string) => void): Promise<Project> {
  const prefs = getPrefs()
  onStage('strength')
  let strength: ImportMeta['strength'] = 'zxcvbn'
  let score: (pw: string) => number
  try { score = await strengthScorer() } catch { score = quickScore; strength = 'built-in' }
  let breach: ImportMeta['breach'] = 'skipped'
  let breached: Map<string, boolean> | undefined
  if (prefs.breachCheck) {
    onStage('breach', '0%')
    const r = await checkBreaches(parsed.items.map(i => i.password), (d, t) => onStage('breach', `${Math.round((d / t) * 100)}%`))
    breached = r.map
    breach = r.failed === 0 ? 'live' : r.map.size ? 'partial' : 'skipped'
  }
  onStage('tfa')
  const tfa = await tfaSet(prefs.tfaLive)
  const findings = await analyze(parsed.items, { score, breached, tfa: tfa.set })
  onStage('saving')
  const now = new Date()
  const meta: ImportMeta = { id: uuid(), kind: 'vault', format: parsed.format, fileName, rows: parsed.rows, items: findings.length, warnings: parsed.issues.length, at: now.getTime(), breach, tfa: tfa.live ? 'live' : 'bundled', strength }
  // A new import supersedes old "rotated" marks: the export now carries the real state.
  const next = { ...p, findings, fixed: {}, imports: [meta, ...p.imports].slice(0, 50) }
  const ctx = context(findings, p.access)
  return saveProject({ ...next, snapshots: [...p.snapshots, snapshot(findings, ctx, uuid(), `Import, ${fmtLabel(now)}`)] })
}

export async function importAccess(p: Project, text: string, fileName: string) {
  const r = parseAccess(text)
  if (r.rows.length) await saveProject({ ...p, access: r.rows, imports: [{ id: uuid(), kind: 'access', format: 'access-list', fileName, rows: r.rows.length + r.issues.length, items: r.rows.length, warnings: r.issues.length, at: Date.now() }, ...p.imports] })
  return r
}

export interface Derived { eff: Finding[]; ctx: Ctx; sum: Summary }
export function derive(p: Project): Derived {
  const eff = applyFixes(p.findings, p.fixed)
  const ctx = context(eff, p.access)
  return { eff, ctx, sum: summarize(eff, ctx) }
}

export function useProject(id: string) {
  const list = useProjects()
  const project = list?.find(p => p.id === id) ?? null
  const d = useMemo(() => project ? derive(project) : null, [project])
  const update = (patch: Partial<Project>) => project && saveProject({ ...project, ...patch })
  return { loading: list === null, project, d, update }
}

export function saveSnapshot(p: Project, label: string) {
  const { eff, ctx } = derive(p)
  return saveProject({ ...p, snapshots: [...p.snapshots, snapshot(eff, ctx, uuid(), label)] })
}
