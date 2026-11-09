import { useRef, useState } from 'react'
import { FORMAT_LABEL, parse1pux, parseExport, type Format, type Issue, type ParseResult } from './engine/formats.ts'
import { readZipEntry } from './engine/unzip.ts'
import { toCsv } from './engine/csv.ts'
import { clearImport, holdImport } from './checks.ts'
import { importAccess, importVault, type Stage } from './projectData.ts'
import { getPrefs, type Project } from './store.ts'
import { download, fmtDate, go, Link, plural, toast } from './ui.tsx'

const MAX = 25 * 1024 * 1024
const STAGES: [Stage, string][] = [['strength', 'Scoring strength (zxcvbn)'], ['breach', 'Checking breaches (k-anonymity)'], ['tfa', 'Matching 2FA support'], ['saving', 'Saving findings']]

async function readExport(file: File, forced?: Format): Promise<ParseResult> {
  if (file.size > MAX) throw new Error(`That file is ${(file.size / 1e6).toFixed(1)} MB; the limit is 25 MB.`)
  const buf = await file.arrayBuffer()
  const head = new Uint8Array(buf.slice(0, 2))
  if (head[0] === 0x50 && head[1] === 0x4b) {
    const data = await readZipEntry(buf, 'export.data')
    if (!data) throw new Error('This zip has no export.data inside. Is it a 1Password .1pux export?')
    return parse1pux(JSON.parse(new TextDecoder().decode(data)))
  }
  const text = new TextDecoder().decode(buf)
  if (text.trimStart().startsWith('{')) {
    const j = JSON.parse(text)
    if (j.accounts) return parse1pux(j)
    throw new Error('JSON exports are not supported yet. Export as CSV instead (see the docs).')
  }
  return parseExport(text, forced)
}

function Report({ r, fileName }: { r: ParseResult; fileName: string }) {
  const errors = r.issues.filter(i => i.level === 'error'), warns = r.issues.filter(i => i.level === 'warn')
  return (
    <div className="validation">
      <div className="row gap wrap">
        <span className={`badge ${errors.length ? 'bad' : 'ok'}`}>{errors.length ? 'Cannot import' : 'Ready'}</span>
        <strong>{fileName}</strong>
        <span className="muted small">Detected: {FORMAT_LABEL[r.format]} · {plural(r.rows, 'row')} · {plural(r.items.length, 'login')} usable</span>
      </div>
      {Object.keys(r.mapping).length > 0 && (
        <dl className="mapping">{Object.entries(r.mapping).map(([k, v]) => <div key={k}><dt>{k}</dt><dd><code>{v}</code></dd></div>)}</dl>
      )}
      {!r.mapping.changed && r.format !== '1password-1pux' && <p className="muted small">No password-changed date in this format, so age checks are skipped. Firefox and generic CSVs with a <code>last_changed</code> column include it.</p>}
      <Issues list={[...errors, ...warns]} />
    </div>
  )
}

function Issues({ list }: { list: Issue[] }) {
  const [all, setAll] = useState(false)
  if (!list.length) return null
  const shown = all ? list : list.slice(0, 8)
  return (
    <>
      <ul className="issues">{shown.map((i, k) => <li key={k} className={i.level}><span className="mono">{i.line ? `line ${i.line}` : 'file'}</span>{i.message}</li>)}</ul>
      {list.length > 8 && <button type="button" className="linkish small" onClick={() => setAll(a => !a)}>{all ? 'Show fewer' : `Show all ${list.length}`}</button>}
    </>
  )
}

function Drop({ label, accept, onFile, hint }: { label: string; accept: string; onFile(f: File): void; hint: string }) {
  const [over, setOver] = useState(false)
  const input = useRef<HTMLInputElement>(null)
  return (
    <div className={`drop${over ? ' over' : ''}`} onDragOver={e => { e.preventDefault(); setOver(true) }} onDragLeave={() => setOver(false)}
      onDrop={e => { e.preventDefault(); setOver(false); const f = e.dataTransfer.files[0]; if (f) onFile(f) }}>
      <div className="drop-icon" aria-hidden="true" />
      <strong>{label}</strong>
      <span className="muted small">{hint}</span>
      <button type="button" className="btn secondary sm" onClick={() => input.current?.click()}>Choose file</button>
      <input ref={input} type="file" accept={accept} hidden onChange={e => { const f = e.target.files?.[0]; if (f) onFile(f); e.target.value = '' }} />
    </div>
  )
}

export function ImportPanel({ p }: { p: Project }) {
  const [file, setFile] = useState<File | null>(null)
  const [forced, setForced] = useState<Format | ''>('')
  const [parsed, setParsed] = useState<ParseResult | null>(null)
  const [err, setErr] = useState<string | null>(null)
  const [stage, setStage] = useState<{ s: Stage; d?: string } | null>(null)
  const [accessIssues, setAccessIssues] = useState<Issue[] | null>(null)

  const load = async (f: File, fmt?: Format) => {
    setErr(null); setParsed(null); setFile(f)
    try { setParsed(await readExport(f, fmt)) } catch (e) { setErr(e instanceof Error ? e.message : String(e)) }
  }
  const run = async () => {
    if (!parsed || !file) return
    try {
      await importVault(p, parsed, file.name, (s, d) => setStage({ s, d }))
      if (getPrefs().autoClear) { for (const it of parsed.items) { it.password = ''; it.username = '' } clearImport() }
      else holdImport(p.id, file.name, parsed.items)
      setParsed(null); setFile(null); setStage(null)
      toast(`Analyzed ${plural(parsed.items.length, 'login')}. Nothing secret was saved.`, { tone: 'ok' })
      go(`/app/p/${p.id}/overview`)
    } catch (e) { setStage(null); setErr(e instanceof Error ? e.message : String(e)) }
  }
  const ready = parsed && !parsed.issues.some(i => i.level === 'error')

  return (
    <div className="stack">
      {p.sampleId && <p className="note">This is a synthetic sample. Importing here replaces its findings with yours; consider a <Link href="/app">new vault check</Link> instead.</p>}
      <div className="split-2">
        <div className="panel">
          <h2>1. Vault export</h2>
          <p className="muted small">CSV from 1Password, Bitwarden, LastPass, Chrome, Edge, Firefox or Apple Passwords, or a 1Password <code>.1pux</code>. <Link href="/docs">Export steps</Link></p>
          {stage ? (
            <ol className="stages" aria-live="polite">
              {STAGES.map(([s, l]) => {
                const i = STAGES.findIndex(x => x[0] === stage.s), k = STAGES.findIndex(x => x[0] === s)
                return <li key={s} className={k < i ? 'done' : k === i ? 'now' : ''}>{l}{k === i && stage.d ? ` ${stage.d}` : ''}</li>
              })}
            </ol>
          ) : (
            <>
              <Drop label="Drop your export here" hint="Read in this tab only. Passwords are never saved." accept=".csv,.1pux,.zip,.txt,text/csv" onFile={f => void load(f, forced || undefined)} />
              <label className="field inline"><span>Format</span>
                <select value={forced} onChange={e => { const v = e.target.value as Format | ''; setForced(v); if (file) void load(file, v || undefined) }}>
                  <option value="">Detect automatically</option>
                  {(Object.keys(FORMAT_LABEL) as Format[]).filter(f => f !== '1password-1pux').map(f => <option key={f} value={f}>{FORMAT_LABEL[f]}</option>)}
                </select>
              </label>
            </>
          )}
          {err && <p className="error" role="alert">{err}</p>}
          {parsed && file && !stage && <Report r={parsed} fileName={file.name} />}
          {parsed && !stage && (
            <div className="row gap wrap">
              <button type="button" className="btn primary" disabled={!ready} onClick={() => void run()}>Analyze {plural(parsed.items.length, 'login')}</button>
              <button type="button" className="btn ghost" onClick={() => { for (const it of parsed.items) it.password = ''; setParsed(null); setFile(null) }}>Discard</button>
            </div>
          )}
          {parsed && <p className="muted small">{getPrefs().breachCheck ? 'Breach check sends only 5-character SHA-1 prefixes to Have I Been Pwned.' : 'Breach check is off in Settings.'}</p>}
        </div>

        <div className="panel">
          <h2>2. Access list <span className="muted small">(optional)</span></h2>
          <p className="muted small">Who can open which vault or item. Powers offboarding and the “shared with N people” signal. Columns: <code>person</code>, <code>vault</code> and/or <code>item</code>, optional <code>role</code> (owner/member).</p>
          <Drop label="Drop an access list CSV" hint="Names or emails. No passwords in this file." accept=".csv,text/csv" onFile={async f => {
            const r = await importAccess(p, await f.text(), f.name)
            setAccessIssues(r.issues)
            if (r.rows.length) toast(`Loaded ${plural(r.rows.length, 'access row')} for ${plural(new Set(r.rows.map(x => x.person)).size, 'person', 'people')}`, { tone: 'ok' })
          }} />
          {accessIssues && <Issues list={accessIssues} />}
          <button type="button" className="linkish small" onClick={() => download('access-list-template.csv', toCsv([['person', 'vault', 'item', 'role'], ['Jordan Lee', 'Marketing & Social', '', 'member'], ['Sofia Alvarez', 'Marketing & Social', '', 'owner'], ['Jordan Lee', '', 'Office Wi-Fi router admin', 'member']]))}>Download a template</button>
          {p.access.length > 0 && <p className="small">Current: {plural(p.access.length, 'row')}, {plural(new Set(p.access.map(a => a.person)).size, 'person', 'people')}, {plural(new Set(p.access.map(a => a.vault).filter(Boolean)).size, 'vault')}.</p>}
        </div>
      </div>

      {p.imports.length > 0 && (
        <div className="panel">
          <h3>Import history</h3>
          <table className="table compact">
            <thead><tr><th>When</th><th>File</th><th>Format</th><th className="num">Items</th><th className="num">Warnings</th><th>Checks</th></tr></thead>
            <tbody>{p.imports.map(i => (
              <tr key={i.id}><td>{fmtDate(i.at)}</td><td className="trunc">{i.fileName}</td><td>{i.format === 'synthetic' ? 'Synthetic' : i.format === 'access-list' ? 'Access list' : FORMAT_LABEL[i.format]}</td><td className="num">{i.items}</td><td className="num">{i.warnings}</td>
                <td className="small muted">{i.kind === 'vault' ? `breach: ${i.breach}, 2FA: ${i.tfa}, strength: ${i.strength}` : '—'}</td></tr>
            ))}</tbody>
          </table>
        </div>
      )}
    </div>
  )
}
