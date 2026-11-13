import { useEffect, useMemo, useState, useSyncExternalStore } from 'react'
import type { Finding } from './engine/analyze.ts'
import { ageDays, compare, fixPlanCsv, isShared, offboard, people, prioritized, reasons, risk, siblings, WEIGHTS } from './engine/risk.ts'
import { entropyBits, generate, SETS } from './engine/password.ts'
import { clearImport, heldImport, subscribeHeld } from './checks.ts'
import { derive, saveSnapshot, today, useProject, type Derived } from './projectData.ts'
import { getPrefs, saveProject, type Project } from './store.ts'
import { deleteSnapshotCloud } from './sync.ts'
import { ask, CopyButton, download, Empty, fmtDate, go, isTyping, Link, Modal, NotFound, plural, signed, SyntheticBadge, toast } from './ui.tsx'
import { BlastGraph, grade, HealthRing, SevPill, Trend } from './viz.tsx'
import { ImportPanel } from './Import.tsx'

const TABS = [['overview', 'Overview'], ['items', 'Items'], ['offboard', 'Offboarding'], ['actions', 'Fix plan'], ['history', 'History'], ['import', 'Import']] as const

export default function ProjectView({ id, tab }: { id: string; tab: string }) {
  const { loading, project: p, d } = useProject(id)
  const [help, setHelp] = useState(false)
  useEffect(() => { if (p) document.title = `${p.name} · Vault Health` }, [p?.name])
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (isTyping(e) || e.metaKey || e.ctrlKey || e.altKey || !p) return
      const n = Number(e.key)
      if (n >= 1 && n <= TABS.length) go(`/app/p/${p.id}/${TABS[n - 1][0]}`, { keepScroll: true })
      else if (e.key === 's' && p.findings.length) void saveSnapshot(p, `Manual snapshot, ${fmtDate(Date.now())}`).then(() => toast('Snapshot saved', { tone: 'ok' }))
      else if (e.key === 'p' && p.findings.length) go(`/app/p/${p.id}/report`)
      else if (e.key === '?') setHelp(true)
    }
    addEventListener('keydown', onKey)
    return () => removeEventListener('keydown', onKey)
  }, [p])

  if (loading) return <div className="boot" role="status"><span className="spinner" /> Opening the vault</div>
  if (!p || !d) return <NotFound />
  const empty = !p.findings.length
  const active = empty && tab !== 'import' && tab !== 'history' ? 'import' : TABS.some(t => t[0] === tab) ? tab : 'overview'
  return (
    <section className="page project">
      <div className="page-head">
        <div>
          <div className="eyebrow"><Link href="/app">Vaults</Link> / {p.sampleId ? 'Sample' : 'Workspace'}</div>
          <h1 className="row gap-sm wrap">{p.name} {p.sampleId && <SyntheticBadge />}</h1>
          {!empty && <p className="muted">{plural(d.sum.n, 'item')} in {plural(new Set(p.findings.map(f => f.vault)).size, 'vault')} · last import {fmtDate(p.imports.find(i => i.kind === 'vault')?.at ?? p.updatedAt)}</p>}
        </div>
        {!empty && <div className="row gap wrap">
          <button type="button" className="btn ghost sm" onClick={() => void saveSnapshot(p, `Manual snapshot, ${fmtDate(Date.now())}`).then(() => toast('Snapshot saved', { tone: 'ok' }))}>Save snapshot</button>
          <Link href={`/app/p/${p.id}/report`} className="btn secondary sm">Printable report</Link>
        </div>}
      </div>
      <HeldBanner projectId={p.id} />
      <nav className="tabs" aria-label="Vault sections">
        {TABS.map(([k, l], i) => <Link key={k} href={`/app/p/${p.id}/${k}`} aria-current={active === k ? 'page' : undefined} className={empty && k !== 'import' && k !== 'history' ? 'disabled' : ''} title={`${l} (${i + 1})`}>{l}</Link>)}
      </nav>
      <div className="tab-body" key={active}>
        {active === 'overview' && <Overview p={p} d={d} />}
        {active === 'items' && <Items p={p} d={d} />}
        {active === 'offboard' && <Offboard p={p} d={d} />}
        {active === 'actions' && <Actions p={p} d={d} />}
        {active === 'history' && <History p={p} />}
        {active === 'import' && <ImportPanel p={p} />}
      </div>
      <Modal open={help} onClose={() => setHelp(false)} title="Keyboard shortcuts">
        <dl className="shortcuts">
          <div><dt><kbd>1</kbd>&ndash;<kbd>6</kbd></dt><dd>Switch tabs</dd></div>
          <div><dt><kbd>S</kbd></dt><dd>Save a snapshot</dd></div>
          <div><dt><kbd>P</kbd></dt><dd>Printable report</dd></div>
          <div><dt><kbd>&#8984;</kbd>/<kbd>Ctrl</kbd> <kbd>Z</kbd></dt><dd>Undo the last delete or rotation</dd></div>
        </dl>
      </Modal>
    </section>
  )
}

function HeldBanner({ projectId }: { projectId: string }) {
  const held = useSyncExternalStore(subscribeHeld, heldImport)
  if (!held || held.projectId !== projectId) return null
  return (
    <div className="held" role="status">
      <span className="lock" aria-hidden="true" />
      <div className="grow"><strong>{held.fileName}</strong> is still in this tab’s memory ({plural(held.items.length, 'login')}). It was never saved. Clear it once you are done re-checking.</div>
      <button type="button" className="btn primary sm" onClick={() => { clearImport(); toast('Cleared the imported file from memory', { tone: 'ok' }) }}>Clear from memory</button>
    </div>
  )
}

export function markRotated(p: Project, ids: string[], on = true) {
  const fixed = { ...p.fixed }
  for (const i of ids) { if (on) fixed[i] = today(); else delete fixed[i] }
  const prev = p.fixed
  void saveProject({ ...p, fixed })
  toast(on ? `Marked ${plural(ids.length, 'item')} as rotated` : 'Unmarked', { undo: () => void saveProject({ ...p, fixed: prev }) })
}

const STAT = (sum: Derived['sum']) => [
  ['Breached', sum.breached, 'Seen in public breach corpora (HIBP)', 'breached'],
  ['Reused', sum.reused, 'Same password as another item', 'reused'],
  ['Near-reused', sum.near, 'A variant of another item’s password', 'near'],
  ['Weak', sum.weak, 'zxcvbn score 0 or 1', 'weak'],
  ['Over a year old', sum.old, 'Password last changed > 365 days ago', 'old'],
  ['2FA not set', sum.missing2fa, 'Site supports TOTP but none is saved', 'no2fa'],
  ['Shared', sum.shared, 'In a shared vault or open to more than one person', 'shared'],
] as const

function Overview({ p, d }: { p: Project; d: Derived }) {
  const [sel, setSel] = useState<string | null>(null)
  const top = prioritized(d.eff, d.ctx).slice(0, 8)
  const selF = sel ? d.eff.find(f => f.id === sel) : null
  const healed = useMemo(() => new Set(Object.keys(p.fixed)), [p.fixed])
  const last = p.snapshots.at(-2)
  const g = grade(d.sum.health)
  const unchecked = p.imports.find(i => i.kind === 'vault')?.breach
  return (
    <div className="stack">
      <div className="overview-top">
        <div className="panel ring-panel">
          <HealthRing sum={d.sum} />
          <div>
            <h2>{g.label}</h2>
            <p className="muted small">100 − ½ × mean item risk − ½ × % of items rated high or critical. <Link href="/docs#scoring">How scoring works</Link></p>
            {last && <p className="small">{signed(d.sum.health - last.summary.health)} since {last.label}</p>}
            {(unchecked === 'skipped' || unchecked === 'partial') && <p className="warn-text small">Breach check {unchecked === 'partial' ? 'only partly ran' : 'was skipped'}; re-import online to complete it.</p>}
            <div className="sev-legend">{(['critical', 'high', 'medium', 'low'] as const).map(s => <span key={s}><i className={`sev-${s}`} />{d.sum.bySeverity[s]} {s}</span>)}</div>
          </div>
        </div>
        <div className="stat-grid">
          {STAT(d.sum).map(([l, n, hint, k]) => (
            <Link key={l} href={`/app/p/${p.id}/items?f=${k}`} className={`stat${n ? ' has' : ''}`} title={hint}><span>{l}</span><strong>{n}</strong></Link>
          ))}
        </div>
      </div>
      <div className="overview-main">
        <div className="panel">
          <div className="row between wrap"><h3>Blast radius</h3><span className="muted small">Lines join items that share a password; dashed lines are near-identical.</span></div>
          <BlastGraph fs={d.eff} ctx={d.ctx} selected={sel} onSelect={setSel} healed={healed} />
          {selF && <ItemDetail p={p} f={selF} d={d} onClose={() => setSel(null)} />}
        </div>
        <div className="panel">
          <div className="row between"><h3>Fix first</h3><Link href={`/app/p/${p.id}/actions`} className="small">Full plan</Link></div>
          {top.length ? <ol className="fix-list">{top.map(({ f, r }) => (
            <li key={f.id}>
              <SevPill r={r} />
              <button type="button" className="linkish grow trunc left" onClick={() => setSel(f.id)}>{f.title}<small className="muted"> {f.vault}</small></button>
              <button type="button" className="btn ghost sm" onClick={() => markRotated(p, [f.id, ...siblings(f, d.eff).map(x => x.id)])}>Rotated</button>
            </li>
          ))}</ol> : <Empty title="Nothing to fix">Every item scores zero risk. Save a snapshot for your records.</Empty>}
        </div>
      </div>
    </div>
  )
}

function ItemDetail({ p, f, d, onClose }: { p: Project; f: Finding; d: Derived; onClose(): void }) {
  const sib = siblings(f, d.eff)
  const rs = reasons(f, d.ctx)
  return (
    <div className="item-detail">
      <div className="row between"><strong>{f.title}</strong><button type="button" className="icon-btn" aria-label="Close details" onClick={onClose}>&times;</button></div>
      <div className="muted small">{f.domain || 'no URL'} · {f.vault}{f.changed ? ` · changed ${fmtDate(f.changed)}` : ''}</div>
      {rs.length ? <ul className="reasons">{rs.map(r => <li key={r.text}>{r.text} <span className="muted">+{r.points}</span></li>)}</ul> : <p className="ok-text small">No issues.</p>}
      {sib.length > 0 && <p className="small">Shares a password with: {sib.map(s => s.title).join(', ')}</p>}
      {rs.length > 0 && <button type="button" className="btn primary sm" onClick={() => { markRotated(p, [f.id, ...sib.map(x => x.id)]); onClose() }}>Mark {sib.length ? `all ${sib.length + 1}` : ''} rotated</button>}
    </div>
  )
}

const FILTERS: Record<string, [string, (f: Finding, d: Derived) => boolean]> = {
  all: ['All', () => true],
  breached: ['Breached', f => !!f.breached],
  reused: ['Reused', (f, d) => !!f.group && (d.ctx.groupSize.get(f.group) ?? 0) > 1],
  // Same rule as the overview count: an item that is already exactly reused is counted under Reused only.
  near: ['Near-reused', (f, d) => !FILTERS.reused[1](f, d) && !!f.near && (d.ctx.nearSize.get(f.near) ?? 0) > 1],
  weak: ['Weak', f => f.strength <= 1],
  old: ['Old', (f, d) => (ageDays(f, d.ctx.now) ?? 0) > 365],
  no2fa: ['2FA not set', f => f.tfa && !f.totp],
  shared: ['Shared', (f, d) => isShared(f, d.ctx)],
  sso: ['SSO candidates', f => f.sso],
}

function Items({ p, d }: { p: Project; d: Derived }) {
  const [filter, setFilter] = useState(() => { const f = new URLSearchParams(location.search).get('f'); return f && f in FILTERS ? f : 'all' })
  const [q, setQ] = useState('')
  const [vault, setVault] = useState('')
  const vaults = [...new Set(d.eff.map(f => f.vault))].sort()
  const rows = d.eff.filter(f => FILTERS[filter][1](f, d) && (!vault || f.vault === vault) && (!q || `${f.title} ${f.domain}`.toLowerCase().includes(q.toLowerCase())))
    .map(f => ({ f, r: risk(f, d.ctx) })).sort((a, b) => b.r - a.r || a.f.title.localeCompare(b.f.title))
  return (
    <div className="stack">
      <div className="toolbar">
        <div className="chips" role="group" aria-label="Filter">
          {Object.entries(FILTERS).map(([k, [l, fn]]) => <button key={k} type="button" className={`chip${filter === k ? ' on' : ''}`} aria-pressed={filter === k} onClick={() => setFilter(k)}>{l} <span>{d.eff.filter(f => fn(f, d)).length}</span></button>)}
        </div>
        <div className="row gap-sm wrap">
          <input type="search" placeholder="Search title or domain" value={q} onChange={e => setQ(e.target.value)} aria-label="Search items" />
          <select value={vault} onChange={e => setVault(e.target.value)} aria-label="Vault"><option value="">All vaults</option>{vaults.map(v => <option key={v}>{v}</option>)}</select>
        </div>
      </div>
      <div className="table-wrap">
        <table className="table">
          <thead><tr><th>Item</th><th>Vault</th><th>Strength</th><th>Changed</th><th>Flags</th><th className="num">Risk</th><th><span className="sr-only">Action</span></th></tr></thead>
          <tbody>
            {rows.map(({ f, r }) => {
              const fixed = !!p.fixed[f.id]
              const sib = siblings(f, d.eff)
              return (
                <tr key={f.id} className={fixed ? 'is-fixed' : ''}>
                  <td><strong>{f.title}</strong><div className="muted small">{f.domain || 'no URL'}</div></td>
                  <td>{f.vault}</td>
                  <td><span className={`meter s${f.strength}`} aria-label={`Strength ${f.strength} of 4`}><i /><i /><i /><i /></span></td>
                  <td className="small">{f.changed ? fmtDate(f.changed) : <span className="muted">unknown</span>}</td>
                  <td><div className="flags">
                    {f.breached && <span className="flag bad">breached</span>}
                    {f.breached === null && <span className="flag">unchecked</span>}
                    {sib.length > 0 && <span className="flag bad" title={sib.map(s => s.title).join(', ')}>{f.group ? 'reused' : 'near'} ×{sib.length + 1}</span>}
                    {f.tfa && !f.totp && <span className="flag warn">2FA off</span>}
                    {f.totp && <span className="flag good">TOTP</span>}
                    {isShared(f, d.ctx) && <span className="flag">shared</span>}
                    {f.sso && <span className="flag info">SSO</span>}
                    {fixed && <span className="flag good">rotated {fmtDate(p.fixed[f.id])}</span>}
                  </div></td>
                  <td className="num"><SevPill r={r} /></td>
                  <td>{fixed ? <button type="button" className="btn ghost sm" onClick={() => markRotated(p, [f.id], false)}>Undo</button> : r > 0 && <button type="button" className="btn ghost sm" onClick={() => markRotated(p, [f.id, ...sib.map(x => x.id)])}>Mark rotated</button>}</td>
                </tr>
              )
            })}
          </tbody>
        </table>
        {!rows.length && <Empty title="No items match">Try another filter.</Empty>}
      </div>
    </div>
  )
}

function Offboard({ p, d }: { p: Project; d: Derived }) {
  const list = people(p.access)
  const planned = Object.keys(p.plans)
  const [person, setPerson] = useState(() => planned[0] ?? (p.sampleId ? (p.sampleId === 'agency' ? 'Jordan Lee' : p.sampleId === 'dental' ? 'Kayla Brooks' : 'Victor Hale') : list[0] ?? ''))
  const [manual, setManual] = useState('')
  const [tagging, setTagging] = useState(false)
  const [gen, setGen] = useState<Finding | null>(null)
  const raw = useMemo(() => derive({ ...p, fixed: {} }), [p.findings, p.access])
  // Order from the un-rotated state so ticking items off does not reshuffle the list.
  const steps = useMemo(() => person ? offboard(person, raw.eff, p.access, raw.ctx, p.tags[person]) : [], [person, raw, p.access, p.tags])
  const plan = p.plans[person]
  const done = plan?.done ?? {}
  const n = steps.filter(s => done[s.finding.id]).length

  const toggle = (id: string, also: string[]) => {
    const prev = p
    const on = !done[id]
    const nextDone = { ...done }
    const fixed = { ...p.fixed }
    for (const i of [id, ...also]) {
      if (on) { nextDone[i] = today(); fixed[i] = today() } else { delete nextDone[i]; delete fixed[i] }
    }
    void saveProject({ ...p, fixed, plans: { ...p.plans, [person]: { created: plan?.created ?? today(), done: nextDone } } })
    if (!on) toast('Unticked', { undo: () => void saveProject(prev) })
  }
  const toggleTag = (fid: string) => {
    const cur = new Set(p.tags[person] ?? [])
    if (cur.has(fid)) cur.delete(fid); else cur.add(fid)
    void saveProject({ ...p, tags: { ...p.tags, [person]: [...cur] } })
  }

  return (
    <div className="stack">
      <div className="panel offboard-head">
        <div className="grow">
          <h2>Who is leaving?</h2>
          <p className="muted small">{list.length ? `${plural(list.length, 'person', 'people')} in the access list.` : 'No access list yet. Import one on the Import tab, or type a name and tag items by hand.'}</p>
          <div className="row gap wrap">
            {list.length > 0 && <select value={list.includes(person) ? person : ''} onChange={e => setPerson(e.target.value)} aria-label="Departing person">
              <option value="" disabled>Choose a person</option>
              {list.map(x => <option key={x} value={x}>{x}{p.plans[x] ? ' (plan started)' : ''}</option>)}
            </select>}
            <form className="row gap-sm" onSubmit={e => { e.preventDefault(); if (manual.trim()) { setPerson(manual.trim()); setManual(''); setTagging(true) } }}>
              <input value={manual} onChange={e => setManual(e.target.value)} placeholder="Or type a name" aria-label="Departing person name" />
              <button className="btn ghost sm">Use</button>
            </form>
            {person && <button type="button" className="btn ghost sm" onClick={() => setTagging(t => !t)}>{tagging ? 'Done tagging' : 'Tag items by hand'}</button>}
          </div>
        </div>
        {person && steps.length > 0 && (
          <div className="progress-box">
            <div className="muted small">Rotation progress</div>
            <strong>{n} / {steps.length}</strong>
            <div className="bar"><i style={{ width: `${(n / steps.length) * 100}%` }} /></div>
            <div className="row gap-sm">
              <Link className="btn ghost sm" href={`/app/p/${p.id}/report?person=${encodeURIComponent(person)}`}>Print checklist</Link>
              {plan && <button type="button" className="linkish small" onClick={async () => {
                if (!(await ask(`Close the plan for ${person}?`, 'Removes the checklist progress. Items already marked rotated stay rotated.', 'Close plan'))) return
                const { [person]: _, ...rest } = p.plans
                const prev = p
                await saveProject({ ...p, plans: rest })
                toast('Plan closed', { undo: () => void saveProject(prev) })
              }}>Close plan</button>}
            </div>
          </div>
        )}
      </div>

      {tagging && person && (
        <div className="panel">
          <h3>Items {person} could open</h3>
          <p className="muted small">Tick anything not covered by the access list (a password they were told over chat counts).</p>
          <div className="tag-grid">{d.eff.map(f => (
            <label key={f.id} className="check"><input type="checkbox" checked={(p.tags[person] ?? []).includes(f.id)} onChange={() => toggleTag(f.id)} /> {f.title} <span className="muted small">{f.vault}</span></label>
          ))}</div>
        </div>
      )}

      {!person ? <Empty title="Pick a person to plan">The checklist lists every item they could open, worst blast radius first.</Empty>
        : !steps.length ? <Empty title={`Nothing reachable for ${person}`}>Import an access list or tag items by hand.</Empty>
        : (
          <ol className="checklist">
            {steps.map((s, i) => {
              const ok = !!done[s.finding.id]
              return (
                <li key={s.finding.id} className={ok ? 'done' : ''}>
                  <label className="tick"><input type="checkbox" checked={ok} onChange={() => toggle(s.finding.id, s.also.map(a => a.id))} aria-label={`Rotated ${s.finding.title}${s.also.length ? ` and ${s.also.length} more` : ''}`} /><span /></label>
                  <div className="grow">
                    <div className="row gap-sm wrap"><span className="step-n">{i + 1}</span><strong>{s.finding.title}{s.also.length ? ` + ${s.also.length} more` : ''}</strong><span className="muted small">{s.finding.domain}</span><SevPill r={s.risk} />{s.finding.sso && <span className="flag info" title="This app commonly supports SAML/OIDC SSO, which removes the shared password entirely">SSO candidate</span>}</div>
                    <div className="small step-meta">
                      <span>Owner: <b>{s.owner}</b></span>
                      <span>Blast radius {s.blast}</span>
                      <span>{s.why.join(' · ')}</span>
                    </div>
                    <div className="small">Rotate the password{s.finding.tfa && !s.finding.totp ? ', turn on 2FA' : ''}{s.audience ? `, then share the new one with the ${s.audience} remaining ${s.audience === 1 ? 'user' : 'users'}` : ''}.</div>
                    {s.also.length > 0 && <div className="also small">Rotate together, same password on: {s.also.map(a => <span key={a.id} className={done[a.id] ? 'struck' : ''}>{a.title}</span>)}</div>}
                  </div>
                  <button type="button" className="btn ghost sm" onClick={() => setGen(s.finding)}>Generate</button>
                </li>
              )
            })}
          </ol>
        )}
      <Modal open={!!gen} onClose={() => setGen(null)} title={gen ? `New password for ${gen.title}` : ''}><Generator /></Modal>
    </div>
  )
}

export function Generator() {
  const [len, setLen] = useState(() => getPrefs().genLength)
  const [use, setUse] = useState<(keyof typeof SETS)[]>(['lower', 'upper', 'digits', 'symbols'])
  const [pw, setPw] = useState(() => generate(len, use))
  const [show, setShow] = useState(true)
  useEffect(() => setPw(generate(len, use)), [len, use])
  return (
    <div className="generator">
      <div className="gen-out"><code className={show ? '' : 'masked'} aria-label="Generated password">{show ? pw : '•'.repeat(pw.length)}</code></div>
      <div className="row gap-sm wrap">
        <CopyButton text={pw} />
        <button type="button" className="btn ghost sm" onClick={() => setPw(generate(len, use))}>Regenerate</button>
        <button type="button" className="btn ghost sm" onClick={() => setShow(s => !s)}>{show ? 'Hide' : 'Show'}</button>
        <span className="muted small">≈{entropyBits(len, use)} bits</span>
      </div>
      <label className="field"><span>Length: {len}</span><input type="range" min="12" max="64" value={len} onChange={e => setLen(Number(e.target.value))} /></label>
      <div className="row gap wrap">{(Object.keys(SETS) as (keyof typeof SETS)[]).map(k => (
        <label key={k} className="check"><input type="checkbox" checked={use.includes(k)} disabled={use.length === 1 && use.includes(k)} onChange={() => setUse(u => u.includes(k) ? u.filter(x => x !== k) : [...u, k])} /> {k}</label>
      ))}</div>
      <p className="muted small">Made with <code>crypto.getRandomValues</code> in this tab. It is not stored or sent anywhere; save it straight into your password manager.</p>
    </div>
  )
}

function Actions({ p, d }: { p: Project; d: Derived }) {
  const plan = prioritized(d.eff, d.ctx)
  return (
    <div className="stack">
      <div className="action-cards">
        <article className="panel">
          <h3>Fix plan (CSV)</h3>
          <p className="muted small">{plural(plan.length, 'item')} with risk, ordered worst first, with the action and reasons. Opens in Excel or Sheets.</p>
          <button type="button" className="btn primary" disabled={!plan.length} onClick={() => download(`${p.name.replace(/\W+/g, '-').toLowerCase()}-fix-plan-${today()}.csv`, fixPlanCsv(d.eff, d.ctx))}>Download CSV</button>
        </article>
        <article className="panel">
          <h3>Printable report</h3>
          <p className="muted small">One page for leadership or your insurer: score, trend, counts, top risks and offboarding status.</p>
          <Link href={`/app/p/${p.id}/report`} className="btn secondary">Open report</Link>
        </article>
        <article className="panel">
          <h3>Policy attestation</h3>
          <p className="muted small">A signed statement that shared passwords are rotated on departure and reviewed on a schedule.{p.attest ? ` Last signed ${fmtDate(p.attest.date)}.` : ''}</p>
          <Link href={`/app/p/${p.id}/attest`} className="btn secondary">{p.attest ? 'View attestation' : 'Prepare attestation'}</Link>
        </article>
      </div>
      <div className="split-2">
        <div className="panel">
          <h3>Prioritized fixes</h3>
          {plan.length ? <ol className="plan-list">{plan.slice(0, 40).map(({ f, r }) => (
            <li key={f.id}><SevPill r={r} /><div className="grow"><strong>{f.title}</strong><div className="muted small">{actionText(f, d)}</div></div></li>
          ))}</ol> : <Empty title="Nothing to fix" />}
          {plan.length > 40 && <p className="muted small">and {plan.length - 40} more in the CSV.</p>}
        </div>
        <div className="panel"><h3>Generate a strong replacement</h3><Generator /></div>
      </div>
    </div>
  )
}
const actionText = (f: Finding, d: Derived) => reasons(f, d.ctx).map(r => r.text).join(' · ')

function History({ p }: { p: Project }) {
  const snaps = [...p.snapshots].sort((a, b) => a.at.localeCompare(b.at))
  const [ai, setAi] = useState(Math.max(0, snaps.length - 2))
  const [bi, setBi] = useState(snaps.length - 1)
  if (!snaps.length) return <Empty title="No snapshots yet">Each import saves one automatically. You can also press <kbd>S</kbd>.</Empty>
  const A = snaps[Math.min(ai, snaps.length - 1)], B = snaps[Math.min(bi, snaps.length - 1)]
  const diff = A && B && A !== B ? compare(A, B) : null
  const title = (id: string) => B.titles[id] ?? A.titles[id] ?? id
  return (
    <div className="stack">
      <div className="panel">
        <h3>Health over time</h3>
        <Trend points={snaps.map(s => ({ label: s.label, v: s.summary.health }))} />
        {snaps.length < 2 && <p className="muted small">Import again next month (or save a snapshot after fixing things) to see a trend.</p>}
      </div>
      {snaps.length > 1 && (
        <div className="panel">
          <div className="row gap wrap compare-pick">
            <label className="field inline"><span>From</span><select value={ai} onChange={e => setAi(Number(e.target.value))}>{snaps.map((s, i) => <option key={s.id} value={i}>{s.label}</option>)}</select></label>
            <label className="field inline"><span>To</span><select value={bi} onChange={e => setBi(Number(e.target.value))}>{snaps.map((s, i) => <option key={s.id} value={i}>{s.label}</option>)}</select></label>
          </div>
          {diff ? (
            <>
              <div className="diff-stats">
                <div><span>Health</span><strong className={diff.healthDelta > 0 ? 'ok-text' : diff.healthDelta < 0 ? 'bad-text' : ''}>{A.summary.health} → {B.summary.health} ({signed(diff.healthDelta)})</strong></div>
                <div><span>Items fixed</span><strong className="ok-text">{diff.fixed.length}</strong></div>
                <div><span>Got worse</span><strong className={diff.worse.length ? 'bad-text' : ''}>{diff.worse.length}</strong></div>
                <div><span>Breached</span><strong>{A.summary.breached} → {B.summary.breached}</strong></div>
                <div><span>Reused</span><strong>{A.summary.reused} → {B.summary.reused}</strong></div>
                <div><span>Added / removed</span><strong>{diff.added.length} / {diff.removed.length}</strong></div>
              </div>
              <div className="split-2">
                <div><h4 className="h4">Fixed</h4>{diff.fixed.length ? <ul className="plain">{diff.fixed.map(id => <li key={id}>{title(id)} <span className="muted small">{A.risks[id]} → {B.risks[id] ?? 'removed'}</span></li>)}</ul> : <p className="muted small">None.</p>}</div>
                <div><h4 className="h4">Worse</h4>{diff.worse.length ? <ul className="plain">{diff.worse.map(id => <li key={id}>{title(id)} <span className="muted small">{A.risks[id]} → {B.risks[id]}</span></li>)}</ul> : <p className="muted small">None.</p>}</div>
              </div>
            </>
          ) : <p className="muted small">Pick two different snapshots.</p>}
        </div>
      )}
      <div className="panel">
        <h3>Snapshots</h3>
        <ul className="snap-list">{[...snaps].reverse().map(s => (
          <li key={s.id}>
            <div className="grow"><strong>{s.label}</strong><div className="muted small">{fmtDate(s.at)} · {plural(s.summary.n, 'item')} · health {s.summary.health}</div></div>
            <button type="button" className="btn danger-ghost sm" onClick={async () => {
              const prev = p
              await saveProject({ ...p, snapshots: p.snapshots.filter(x => x.id !== s.id) })
              void deleteSnapshotCloud(s.id)
              toast('Snapshot deleted', { undo: () => void saveProject(prev) })
            }}>Delete</button>
          </li>
        ))}</ul>
      </div>
    </div>
  )
}

