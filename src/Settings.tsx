import { useState } from 'react'
import { deleteProject, getPrefs, getProjects, setPrefs, type Prefs } from './store.ts'
import { exportAll, useSync } from './sync.ts'
import { ask, download, setTheme, toast, useDark } from './ui.tsx'

export default function Settings() {
  const [d, setD] = useState<Prefs>(getPrefs)
  const dark = useDark()
  const sync = useSync()
  const save = (p: Partial<Prefs>) => { const next = { ...d, ...p }; setD(next); setPrefs(next); toast('Saved', { tone: 'ok', ttl: 1500 }) }

  return (
    <section className="page narrow settings">
      <div className="eyebrow">Settings</div>
      <h1>Settings</h1>

      <div className="panel">
        <h2>Checks</h2>
        <label className="check"><input type="checkbox" checked={d.breachCheck} onChange={e => save({ breachCheck: e.target.checked })} /> Check passwords against Have I Been Pwned (sends 5-character SHA-1 prefixes only)</label>
        <label className="check"><input type="checkbox" checked={d.tfaLive} onChange={e => save({ tfaLive: e.target.checked })} /> Download the live 2fa.directory dataset (otherwise use the built-in list)</label>
        <label className="check"><input type="checkbox" checked={d.autoClear} onChange={e => save({ autoClear: e.target.checked })} /> Clear the imported file from memory as soon as analysis finishes</label>
        <label className="field"><span>Default generated password length: {d.genLength}</span><input type="range" min="12" max="64" value={d.genLength} onChange={e => save({ genLength: Number(e.target.value) })} /></label>
      </div>

      <div className="panel">
        <h2>Appearance</h2>
        <div className="seg-control" role="radiogroup" aria-label="Theme">
          <button type="button" role="radio" aria-checked={!dark} className={!dark ? 'on' : ''} onClick={() => setTheme('light')}>Light</button>
          <button type="button" role="radio" aria-checked={dark} className={dark ? 'on' : ''} onClick={() => setTheme('dark')}>Dark</button>
        </div>
      </div>

      <div className="panel">
        <h2>Your data</h2>
        <p>Findings live in this browser (IndexedDB). {sync.user ? <>Signed in as <b>{sync.user.email}</b>: findings, plans and snapshots sync to your account.</> : 'Sign in from the account menu (top right) to sync across devices. It is optional.'} Passwords are never stored either way.</p>
        <div className="row gap wrap">
          <button type="button" className="btn ghost" onClick={async () => download(`vault-health-export-${new Date().toISOString().slice(0, 10)}.json`, await exportAll())}>Export all my data (JSON)</button>
          <button type="button" className="btn danger-ghost" onClick={async () => {
            const list = getProjects()
            if (!list.length) { toast('Nothing to delete'); return }
            if (!(await ask('Delete all vault checks?', `Removes ${list.length} workspace${list.length > 1 ? 's' : ''} from this browser${sync.user ? ' and from your cloud account' : ''}. You can undo for a few seconds.`, 'Delete everything'))) return
            const undos = await Promise.all(list.map(p => deleteProject(p.id)))
            toast(`Deleted ${list.length}`, { undo: () => { for (const u of undos) void u() } })
          }}>Delete everything</button>
        </div>
      </div>

      <div className="panel">
        <h2>Keyboard shortcuts</h2>
        <dl className="shortcuts">
          <div><dt><kbd>1</kbd>&ndash;<kbd>6</kbd></dt><dd>Switch tabs in a vault</dd></div>
          <div><dt><kbd>S</kbd></dt><dd>Save a snapshot</dd></div>
          <div><dt><kbd>P</kbd></dt><dd>Printable report</dd></div>
          <div><dt><kbd>&#8984;</kbd>/<kbd>Ctrl</kbd> <kbd>Z</kbd></dt><dd>Undo the last delete or rotation</dd></div>
          <div><dt><kbd>?</kbd></dt><dd>Show shortcuts in a vault</dd></div>
        </dl>
      </div>
    </section>
  )
}
