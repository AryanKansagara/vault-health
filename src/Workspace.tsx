import { useEffect, useMemo, useState } from 'react'
import { SAMPLES } from './engine/sample.ts'
import { createSampleProject, derive } from './projectData.ts'
import { blankProject, deleteProject, saveProject, useProjects, type Project } from './store.ts'
import { useSync } from './sync.ts'
import { ask, fmtDate, go, Link, plural, SyntheticBadge, toast } from './ui.tsx'
import { grade } from './viz.tsx'

export default function Workspace() {
  const list = useProjects()
  const sync = useSync()
  const [busy, setBusy] = useState<string | null>(null)

  // /app?sample=agency opens (or creates) the sample straight away.
  useEffect(() => {
    const q = new URLSearchParams(location.search)
    const s = q.get('sample'), tab = q.get('tab')?.replace(/[^a-z]/g, '')
    if (!s || list === null || busy || !SAMPLES.some(x => x.id === s)) return
    setBusy(s)
    void createSampleProject(s).then(p => go(`/app/p/${p.id}${tab ? '/' + tab : ''}`, { replace: true }))
  }, [list, busy])

  const openSample = async (id: string) => { setBusy(id); const p = await createSampleProject(id); go(`/app/p/${p.id}`) }
  const newProject = async () => {
    const n = (list?.filter(p => !p.sampleId).length ?? 0) + 1
    const p = await saveProject(blankProject(n === 1 ? 'Company vault' : `Vault ${n}`))
    go(`/app/p/${p.id}/import`)
  }

  if (list === null || busy) return <div className="boot" role="status"><span className="spinner" /> {busy ? 'Analyzing the synthetic vault' : 'Opening your vaults'}</div>

  return (
    <section className="page">
      <div className="page-head">
        <div>
          <div className="eyebrow">Workspace</div>
          <h1>Vaults</h1>
          <p className="muted">One workspace per company or password manager. Each keeps its findings, offboarding plans and a snapshot per import. {sync.user ? 'Synced to your account.' : 'Stored on this device.'}</p>
        </div>
        {list.length > 0 && <button type="button" className="btn primary" onClick={newProject}>New vault check</button>}
      </div>

      {list.length === 0 ? (
        <div className="onboard">
          <article className="onboard-card feature">
            <div className="eyebrow">Two minutes</div>
            <h2>Try the sample</h2>
            <p>Synthetic teams with the usual mess: a social login on six sites, seasonal passwords, a router password from 2019, and someone leaving.</p>
            <div className="stack-sm">
              {SAMPLES.map(s => (
                <button key={s.id} type="button" className="sample-btn" onClick={() => void openSample(s.id)}>
                  <span><strong>{s.name}</strong><small>{s.blurb}</small></span><span aria-hidden="true">&rarr;</span>
                </button>
              ))}
            </div>
          </article>
          <article className="onboard-card">
            <div className="eyebrow">Your vault</div>
            <h2>Import your data</h2>
            <p>Export a CSV (or a 1Password .1pux) from your password manager and drop it in. Optionally add a vault access list so offboarding knows who could see what.</p>
            <div className="row gap wrap">
              <button type="button" className="btn primary" onClick={newProject}>Import your data</button>
              <Link href="/docs" className="btn ghost">Export steps</Link>
            </div>
            <p className="muted small">The file is read in this tab. Passwords are never stored. <Link href="/security">How</Link></p>
          </article>
        </div>
      ) : (
        <>
          <div className="project-grid">{list.map(p => <Card key={p.id} p={p} />)}</div>
          <div className="samples-row">
            <span className="muted small">Samples:</span>
            {SAMPLES.map(s => <button key={s.id} type="button" className="linkish small" onClick={() => void openSample(s.id)}>{s.name}</button>)}
          </div>
        </>
      )}
    </section>
  )
}

function Card({ p }: { p: Project }) {
  const [renaming, setRenaming] = useState(false)
  const d = useMemo(() => derive(p), [p])
  const g = grade(d.sum.health)
  const open = Object.entries(p.plans).filter(([person]) => person).length
  return (
    <article className="project-card">
      <div className="row between">
        {renaming ? (
          <form onSubmit={e => { e.preventDefault(); const v = String(new FormData(e.currentTarget).get('n')).trim(); if (v) void saveProject({ ...p, name: v }); setRenaming(false) }}>
            <input name="n" defaultValue={p.name} autoFocus aria-label="Vault name" onBlur={e => e.currentTarget.form?.requestSubmit()} />
          </form>
        ) : <h3><Link href={`/app/p/${p.id}`}>{p.name}</Link></h3>}
        {p.sampleId && <SyntheticBadge />}
      </div>
      {p.findings.length ? (
        <div className="card-score">
          <span className={`score-chip tone-${g.tone}`}>{d.sum.health}</span>
          <div><strong>{g.label}</strong><div className="muted small">{plural(d.sum.n, 'item')} · {d.sum.breached} breached · {d.sum.reused} reused</div></div>
        </div>
      ) : <p className="muted small">No import yet. <Link href={`/app/p/${p.id}/import`}>Import an export</Link></p>}
      <dl className="mini-stats">
        <div><dt>Snapshots</dt><dd>{p.snapshots.length}</dd></div>
        <div><dt>Offboarding plans</dt><dd>{open}</dd></div>
        <div><dt>Rotated</dt><dd>{Object.keys(p.fixed).length}</dd></div>
      </dl>
      <div className="row between">
        <span className="muted small">Updated {fmtDate(p.updatedAt)}</span>
        <div className="row gap-sm">
          <button type="button" className="btn ghost sm" onClick={() => setRenaming(true)}>Rename</button>
          <button type="button" className="btn danger-ghost sm" onClick={async () => {
            if (!(await ask(`Delete “${p.name}”?`, 'Removes the findings, plans and snapshots from this device (and the cloud, if you are signed in). You can undo for a few seconds.', 'Delete'))) return
            const undo = await deleteProject(p.id)
            toast(`Deleted ${p.name}`, { undo: () => void undo() })
          }}>Delete</button>
        </div>
      </div>
    </article>
  )
}
