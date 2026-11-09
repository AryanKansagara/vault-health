import { useEffect, useMemo, useState } from 'react'
import type { Finding } from './engine/analyze.ts'
import type { Access } from './engine/formats.ts'
import { applyFixes, context, prioritized, reasons, siblings, summarize } from './engine/risk.ts'
import { SAMPLES } from './engine/sample.ts'
import { sampleFindings, today } from './projectData.ts'
import { Link, plural, SyntheticBadge } from './ui.tsx'
import { BlastGraph, grade, HealthRing, SevPill } from './viz.tsx'

function Hero() {
  const [base, setBase] = useState<{ findings: Finding[]; access: Access[] } | null>(null)
  const [fixed, setFixed] = useState<Record<string, string>>({})
  const [sel, setSel] = useState<string | null>(null)
  useEffect(() => { void sampleFindings('agency').then(setBase) }, [])
  const d = useMemo(() => {
    if (!base) return null
    const eff = applyFixes(base.findings, fixed)
    const ctx = context(eff, base.access)
    return { eff, ctx, sum: summarize(eff, ctx), top: prioritized(eff, ctx).slice(0, 4) }
  }, [base, fixed])
  const healed = useMemo(() => new Set(Object.keys(fixed)), [fixed])

  if (!d) return <div className="hero-demo skeleton" aria-busy="true" />
  const selF = sel ? d.eff.find(f => f.id === sel) ?? null : null
  const rotate = (f: Finding) => {
    // Rotating a reused password means rotating every site that shares it.
    const ids = [f.id, ...siblings(f, d.eff).map(x => x.id)]
    setFixed(x => ({ ...x, ...Object.fromEntries(ids.map(i => [i, today()])) }))
    setSel(null)
  }
  const g = grade(d.sum.health)
  return (
    <div className="hero-demo">
      <div className="hero-demo-head">
        <span className="dot-live" aria-hidden="true" /> Live engine · Northwind Creative <SyntheticBadge />
        {Object.keys(fixed).length > 0 && <button type="button" className="linkish small" onClick={() => { setFixed({}); setSel(null) }}>Reset</button>}
      </div>
      <div className="hero-demo-body">
        <div className="hero-ring-col">
          <HealthRing sum={d.sum} size={190} />
          <dl className="hero-stats">
            <div><dt>Breached</dt><dd className={d.sum.breached ? 'bad' : ''}>{d.sum.breached}</dd></div>
            <div><dt>Reused</dt><dd className={d.sum.reused ? 'bad' : ''}>{d.sum.reused}</dd></div>
            <div><dt>Over a year old</dt><dd>{d.sum.old}</dd></div>
          </dl>
        </div>
        <div className="hero-graph-col">
          <BlastGraph fs={d.eff} ctx={d.ctx} selected={sel} onSelect={setSel} healed={healed} height={360} />
        </div>
      </div>
      <div className="hero-actions" aria-live="polite">
        {selF ? (
          <div className="hero-pick">
            <div><strong>{selF.title}</strong> <span className="muted small">{selF.vault}</span>
              <ul className="reasons">{reasons(selF, d.ctx).map(r => <li key={r.text}>{r.text} <span className="muted">+{r.points}</span></li>)}</ul>
            </div>
            {reasons(selF, d.ctx).length ? <button type="button" className="btn primary sm" onClick={() => rotate(selF)}>Rotate{siblings(selF, d.eff).length ? ` all ${siblings(selF, d.eff).length + 1}` : ''}</button> : <span className="ok-text small">Healthy</span>}
          </div>
        ) : d.top.length ? (
          <ol className="hero-top">
            {d.top.map(({ f, r }) => (
              <li key={f.id}>
                <SevPill r={r} /><span className="grow trunc">{f.title}</span>
                <button type="button" className="btn ghost sm" onClick={() => rotate(f)} aria-label={`Rotate ${f.title}`}>Rotate</button>
              </li>
            ))}
          </ol>
        ) : <p className="ok-text center">Every item is healthy. That took {Object.keys(fixed).length} rotations.</p>}
      </div>
      <p className="sr-only" aria-live="polite">Vault health {d.sum.health}, {g.label}</p>
    </div>
  )
}

const EVIDENCE = [
  ['Avoid shared accounts', 'The top answer in a long sysadmin thread on onboarding and offboarding: every shared login is a password nobody can revoke from one person.'],
  ['Rotate when admins leave', 'The second most common answer. The hard part is knowing which shared passwords the person could actually see.'],
  ['The vault knows who saw what', 'Admins point out that a password manager can tell you which shared items a departing employee had access to. Vault Health turns that into an ordered checklist.'],
  ['SSO fixes it, at a price', 'SSO removes the shared password entirely, but many vendors gate it behind an enterprise tier (the "SSO tax"). We flag the apps where it is worth paying.'],
  ['Insurers want proof', 'Cyber insurance questionnaires increasingly ask for documented shared-password resets. You get a printable report and an attestation page.'],
  ['People keep asking for it', 'Password manager users ask for reports that show shared items and reused passwords across the whole team, not one person at a time.'],
]

export function Landing() {
  return (
    <>
      <section className="hero">
        <div className="hero-copy">
          <div className="eyebrow">Credential hygiene and offboarding</div>
          <h1>Someone leaves on Friday. Know exactly which passwords to change.</h1>
          <p className="lede">Drop in your password manager export. Vault Health finds breached, reused and stale passwords, then gives you a rotation checklist for a departing teammate, ordered by blast radius. Passwords never leave your browser.</p>
          <div className="row gap wrap">
            <Link href="/app?sample=agency" className="btn primary lg">Try the sample vault</Link>
            <Link href="/app" className="btn secondary lg">Check your vault</Link>
          </div>
          <p className="muted small hero-note">Works with 1Password, Bitwarden, LastPass, Chrome, Edge, Firefox and Apple Passwords exports. No account needed.</p>
        </div>
        <Hero />
      </section>

      <section className="band">
        <div className="container">
          <div className="eyebrow">Why this exists</div>
          <h2>What admins actually say about offboarding</h2>
          <p className="muted max-60">Paraphrased from public discussions on r/sysadmin, r/1Password and r/Bitwarden.</p>
          <div className="quote-grid">{EVIDENCE.map(([t, b]) => <article key={t} className="quote"><h3>{t}</h3><p>{b}</p></article>)}</div>
        </div>
      </section>

      <section className="container steps">
        <div className="eyebrow">How it works</div>
        <h2>From a messy export to a signed-off rotation</h2>
        <ol className="step-grid">
          <li><b>1</b><h3>Import</h3><p>Export from your password manager and drop the file in. The format is detected, each row is validated, and problems are listed by line number.</p></li>
          <li><b>2</b><h3>Analyze</h3><p>Strength (zxcvbn), exact and near reuse (<code>Summer2024!</code> vs <code>Summer2025!</code>), breach check via k-anonymity, age, missing 2FA and shared-vault exposure. Each item gets a score with the reasons behind it.</p></li>
          <li><b>3</b><h3>Offboard</h3><p>Pick the person who is leaving. You get every item they could open, ordered by blast radius, with an owner, the siblings that share the password and an SSO flag. Tick items off over several days.</p></li>
          <li><b>4</b><h3>Prove it</h3><p>Download a prioritized fix plan as CSV, print a report for leadership or your insurer, and sign a policy attestation. Snapshots show the trend.</p></li>
        </ol>
      </section>

      <section className="band dark-band">
        <div className="container split">
          <div>
            <div className="eyebrow">Security by design</div>
            <h2>Built so that it never has your passwords</h2>
            <p>The export is parsed in this tab. Breach checks send only the first five characters of each SHA-1 hash, with padding. Only derived findings are saved: title, domain, vault, a strength score and yes/no flags. Clear the file from memory with one click.</p>
            <Link href="/security" className="btn secondary">Read the security model</Link>
          </div>
          <ul className="checks">
            <li>No passwords in IndexedDB, localStorage or the cloud</li>
            <li>No usernames stored, either</li>
            <li>Reuse detection uses a salted hash; the salt is discarded after each import</li>
            <li>Strict Content Security Policy: the page can only talk to HIBP, 2fa.directory and the optional sync server</li>
            <li>Generated replacement passwords use <code>crypto.getRandomValues</code> and are never stored</li>
          </ul>
        </div>
      </section>

      <section className="container samples-band">
        <div className="eyebrow">Samples</div>
        <h2>Three synthetic teams to try</h2>
        <div className="sample-cards">
          {SAMPLES.map(s => (
            <Link key={s.id} href={`/app?sample=${s.id}`} className="sample-card">
              <div className="row between"><strong>{s.name}</strong><SyntheticBadge /></div>
              <p>{s.blurb}</p>
              <span className="muted small">{plural(s.people, 'person', 'people')} · departing: {s.departing}</span>
            </Link>
          ))}
        </div>
      </section>

      <section className="container cta">
        <h2>Friday is coming.</h2>
        <p className="muted">Five minutes from export to checklist.</p>
        <div className="row gap center-x wrap"><Link href="/app" className="btn primary lg">Check your vault</Link><Link href="/docs" className="btn ghost lg">How to export</Link></div>
      </section>
    </>
  )
}
