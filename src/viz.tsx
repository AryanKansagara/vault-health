import { useEffect, useMemo, useRef, useState } from 'react'
import type { Finding } from './engine/analyze.ts'
import { risk, severity, type Ctx, type Severity, type Summary } from './engine/risk.ts'

export const grade = (h: number) => (h >= 85 ? { label: 'Healthy', tone: 'good' } : h >= 65 ? { label: 'Needs attention', tone: 'warn' } : { label: 'At risk', tone: 'bad' }) as { label: string; tone: 'good' | 'warn' | 'bad' }

/** Animates a number toward its target. */
export function useTween(target: number, ms = 700) {
  const [v, setV] = useState(target)
  const from = useRef(target)
  useEffect(() => {
    if (matchMedia('(prefers-reduced-motion: reduce)').matches) { setV(target); from.current = target; return }
    const start = performance.now(), a = from.current
    let raf = 0
    const step = (t: number) => {
      const k = Math.min(1, (t - start) / ms), e = 1 - (1 - k) ** 3
      const x = a + (target - a) * e
      setV(x); from.current = x
      if (k < 1) raf = requestAnimationFrame(step)
    }
    raf = requestAnimationFrame(step)
    return () => cancelAnimationFrame(raf)
  }, [target, ms])
  return v
}

/** Score ring with severity segments around the inside. */
export function HealthRing({ sum, size = 220, label = 'Vault health' }: { sum: Summary; size?: number; label?: string }) {
  const h = useTween(sum.health)
  const g = grade(sum.health)
  const r = 44, c = 2 * Math.PI * r
  const sev: Severity[] = ['critical', 'high', 'medium', 'low']
  const total = Math.max(1, sum.n)
  let acc = 0
  const r2 = 35, c2 = 2 * Math.PI * r2
  return (
    <figure className={`ring tone-${g.tone}`} style={{ width: size, height: size }} aria-label={`${label}: ${sum.health} out of 100, ${g.label}`} role="img">
      <svg viewBox="0 0 100 100" aria-hidden="true">
        <circle cx="50" cy="50" r={r} className="ring-track" />
        <circle cx="50" cy="50" r={r} className="ring-arc" strokeDasharray={`${(h / 100) * c} ${c}`} transform="rotate(-90 50 50)" />
        {sev.map(s => {
          const len = (sum.bySeverity[s] / total) * c2
          const el = <circle key={s} cx="50" cy="50" r={r2} className={`ring-sev sev-${s}`} strokeDasharray={`${Math.max(0, len - 0.6)} ${c2}`} strokeDashoffset={-acc} transform="rotate(-90 50 50)" />
          acc += len
          return el
        })}
      </svg>
      <figcaption>
        <strong>{Math.round(h)}</strong>
        <span>{g.label}</span>
      </figcaption>
    </figure>
  )
}

interface Node { f: Finding; x: number; y: number; r: number; risk: number; sev: Severity }

/**
 * Vaults are clusters around a circle; each item is a dot sized by risk. Lines join items that share a password
 * (solid) or a near-identical one (dashed). Rotating an item cuts its lines and turns it green.
 */
export function BlastGraph({ fs, ctx, selected, onSelect, height = 420, width = 640, healed }: { fs: Finding[]; ctx: Ctx; selected?: string | null; onSelect?: (id: string) => void; height?: number; width?: number; healed?: Set<string> }) {
  const W = width, H = height
  const layout = useMemo(() => {
    const vaults = [...new Set(fs.map(f => f.vault))]
    const R = Math.min(W, H) / 2 - Math.min(W, H) / 6
    const nodes = new Map<string, Node>()
    const labels: { v: string; x: number; y: number; anchor: 'start' | 'end' | 'middle' }[] = []
    vaults.forEach((v, i) => {
      const a = (i / vaults.length) * Math.PI * 2 - Math.PI / 2
      const cx = W / 2 + Math.cos(a) * R * (vaults.length > 1 ? 1 : 0), cy = H / 2 + Math.sin(a) * R * (vaults.length > 1 ? 0.92 : 0)
      const items = fs.filter(f => f.vault === v)
      const ring = Math.min(W / 10, 14 + items.length * 4)
      items.forEach((f, j) => {
        const b = (j / items.length) * Math.PI * 2 + i
        const rr = items.length === 1 ? 0 : ring * (0.55 + 0.45 * ((j * 7) % 5) / 4)
        const rk = risk(f, ctx)
        nodes.set(f.id, { f, x: cx + Math.cos(b) * rr, y: cy + Math.sin(b) * rr, r: 4 + rk / 14, risk: rk, sev: severity(rk) })
      })
      const lx = W / 2 + Math.cos(a) * (R + ring + 18), ly = H / 2 + Math.sin(a) * (R * 0.92 + ring + 14)
      const anchor = Math.abs(Math.cos(a)) < 0.3 ? 'middle' as const : Math.cos(a) > 0 ? 'start' as const : 'end' as const
      const room = v.length * 6.2
      labels.push({ v, x: anchor === 'start' ? Math.min(lx, W - room) : anchor === 'end' ? Math.max(lx, room) : Math.max(room / 2, Math.min(W - room / 2, lx)), y: Math.max(14, Math.min(H - 6, ly)), anchor })
    })
    const edges: { a: Node; b: Node; near: boolean; key: string }[] = []
    const list = [...nodes.values()]
    for (let i = 0; i < list.length; i++) for (let j = i + 1; j < list.length; j++) {
      const A = list[i].f, B = list[j].f
      if (A.group && A.group === B.group) edges.push({ a: list[i], b: list[j], near: false, key: A.id + B.id })
      else if (A.near && A.near === B.near) edges.push({ a: list[i], b: list[j], near: true, key: A.id + B.id })
    }
    return { nodes: list, edges, labels }
  }, [fs, ctx, H, W])

  const sel = selected ? layout.nodes.find(n => n.f.id === selected) : null
  return (
    <svg className="blast" viewBox={`0 0 ${W} ${H}`} role="img" aria-label={`Blast radius graph: ${layout.nodes.length} items in ${layout.labels.length} vaults, ${layout.edges.length} shared-password links`}>
      <defs>
        <radialGradient id="glow"><stop offset="0" stopColor="var(--crit)" stopOpacity=".35" /><stop offset="1" stopColor="var(--crit)" stopOpacity="0" /></radialGradient>
      </defs>
      {layout.edges.map(e => {
        const mx = (e.a.x + e.b.x) / 2 + (W / 2 - (e.a.x + e.b.x) / 2) * 0.35, my = (e.a.y + e.b.y) / 2 + (H / 2 - (e.a.y + e.b.y) / 2) * 0.35
        const hot = sel && (sel.f.id === e.a.f.id || sel.f.id === e.b.f.id)
        return <path key={e.key} d={`M${e.a.x},${e.a.y} Q${mx},${my} ${e.b.x},${e.b.y}`} className={`edge${e.near ? ' near' : ''}${hot ? ' hot' : ''}`} />
      })}
      {layout.nodes.filter(n => n.sev === 'critical').map(n => <circle key={'g' + n.f.id} cx={n.x} cy={n.y} r={n.r * 3} fill="url(#glow)" className="pulse" />)}
      {layout.nodes.map(n => (
        <g key={n.f.id} className={`node sev-${n.sev}${healed?.has(n.f.id) ? ' healed' : ''}${selected === n.f.id ? ' sel' : ''}`} transform={`translate(${n.x},${n.y})`}
          onClick={onSelect ? () => onSelect(n.f.id) : undefined} tabIndex={onSelect ? 0 : undefined} role={onSelect ? 'button' : undefined}
          aria-label={onSelect ? `${n.f.title}, risk ${n.risk}` : undefined}
          onKeyDown={onSelect ? e => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); onSelect(n.f.id) } } : undefined}>
          <circle r={n.r} />
          <title>{`${n.f.title} · ${n.f.vault} · risk ${n.risk}`}</title>
        </g>
      ))}
      {layout.labels.map(l => <text key={l.v} x={l.x} y={l.y} textAnchor={l.anchor} className="vault-label">{l.v}</text>)}
    </svg>
  )
}

/** Small line chart of health across snapshots. */
export function Trend({ points }: { points: { label: string; v: number }[] }) {
  if (points.length < 2) return null
  const W = 560, H = 160, P = 28
  const x = (i: number) => P + (i / (points.length - 1)) * (W - 2 * P)
  const y = (v: number) => H - P - (v / 100) * (H - 2 * P)
  const d = points.map((p, i) => `${i ? 'L' : 'M'}${x(i)},${y(p.v)}`).join(' ')
  return (
    <svg className="trend" viewBox={`0 0 ${W} ${H}`} role="img" aria-label={`Health trend: ${points.map(p => `${p.label} ${p.v}`).join(', ')}`}>
      {[0, 50, 100].map(v => <g key={v}><line x1={P} x2={W - P} y1={y(v)} y2={y(v)} className="grid" /><text x={4} y={y(v) + 4} className="axis">{v}</text></g>)}
      <path d={`${d} L${x(points.length - 1)},${y(0)} L${x(0)},${y(0)} Z`} className="area" />
      <path d={d} className="line" />
      {points.map((p, i) => <g key={i}><circle cx={x(i)} cy={y(p.v)} r="4.5" className="pt" /><text x={x(i)} y={y(p.v) - 10} textAnchor="middle" className="val">{p.v}</text></g>)}
    </svg>
  )
}

export const SevPill = ({ r }: { r: number }) => { const s = severity(r); return <span className={`sev-pill sev-${s}`}>{s}<b>{r}</b></span> }
