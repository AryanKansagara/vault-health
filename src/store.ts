import { useSyncExternalStore } from 'react'
import type { Finding } from './engine/analyze.ts'
import type { Access, Format } from './engine/formats.ts'
import type { Snapshot } from './engine/risk.ts'

export interface ImportMeta {
  id: string
  kind: 'vault' | 'access'
  format: Format | 'access-list' | 'synthetic'
  fileName: string
  rows: number
  items: number
  warnings: number
  at: number
  /** How breach and 2FA checks ran for this import. */
  breach?: 'live' | 'partial' | 'skipped' | 'sample'
  tfa?: 'live' | 'bundled'
  strength?: 'zxcvbn' | 'built-in'
}

export interface Plan { created: string; done: Record<string, string> }

export interface Attestation { org: string; signer: string; role: string; date: string; reviewEvery: string; statements: Record<string, boolean> }

/** Everything here is derived. No passwords, usernames or password hashes are ever stored. */
export interface Project {
  id: string
  name: string
  createdAt: number
  updatedAt: number
  sampleId?: string
  findings: Finding[]
  access: Access[]
  /** Manual "this person could open it" tags: person -> finding ids. */
  tags: Record<string, string[]>
  /** Items marked as rotated: finding id -> ISO date. */
  fixed: Record<string, string>
  plans: Record<string, Plan>
  imports: ImportMeta[]
  snapshots: Snapshot[]
  attest?: Attestation
}

// ---------- Tiny IndexedDB wrapper (falls back to memory in private modes) ----------

let dbp: Promise<IDBDatabase | null> | null = null
function db(): Promise<IDBDatabase | null> {
  return dbp ??= new Promise(res => {
    try {
      const req = indexedDB.open('vault-health', 1)
      req.onupgradeneeded = () => { req.result.createObjectStore('projects', { keyPath: 'id' }) }
      req.onsuccess = () => res(req.result)
      req.onerror = () => res(null)
    } catch { res(null) }
  })
}
const mem = new Map<string, Project>()

async function tx<T>(mode: IDBTransactionMode, fn: (s: IDBObjectStore) => IDBRequest<T>): Promise<T> {
  const d = await db()
  if (!d) throw new Error('no-idb')
  return new Promise((res, rej) => {
    const r = fn(d.transaction('projects', mode).objectStore('projects'))
    r.onsuccess = () => res(r.result)
    r.onerror = () => rej(r.error)
  })
}

// ---------- In-memory project list with subscribers ----------

let projects: Project[] = []
let loaded = false
const subs = new Set<() => void>()
const emit = () => { projects = [...projects]; subs.forEach(f => f()) }
const changeHooks = new Set<(p: Project) => void>()
export const onProjectChange = (f: (p: Project) => void) => { changeHooks.add(f); return () => changeHooks.delete(f) }

export async function loadProjects() {
  try { projects = await tx('readonly', s => s.getAll()) as Project[] } catch { projects = [...mem.values()] }
  projects.sort((a, b) => b.updatedAt - a.updatedAt)
  loaded = true
  emit()
}

export function useProjects() {
  return useSyncExternalStore(f => { subs.add(f); return () => subs.delete(f) }, () => loaded ? projects : null)
}
export const getProjects = () => projects
export const getProject = (id: string) => projects.find(p => p.id === id)

export async function saveProject(p: Project, opts: { touch?: boolean; silent?: boolean } = {}) {
  const next = opts.touch === false ? p : { ...p, updatedAt: Date.now() }
  try { await tx('readwrite', s => s.put(next)) } catch { mem.set(next.id, next) }
  const i = projects.findIndex(x => x.id === p.id)
  if (i >= 0) projects[i] = next
  else projects.unshift(next)
  projects.sort((a, b) => b.updatedAt - a.updatedAt)
  emit()
  if (!opts.silent) changeHooks.forEach(f => f(next))
  return next
}

/** Deletes locally; returns an undo function. */
export async function deleteProject(id: string): Promise<() => Promise<void>> {
  const p = getProject(id)
  projects = projects.filter(x => x.id !== id)
  emit()
  try { await tx('readwrite', s => s.delete(id)) } catch { mem.delete(id) }
  addTombstone(id)
  return async () => { if (!p) return; removeTombstone(id); await saveProject(p) }
}

export const uuid = () => crypto.randomUUID()

export function blankProject(name: string): Project {
  const now = Date.now()
  return { id: uuid(), name, createdAt: now, updatedAt: now, findings: [], access: [], tags: {}, fixed: {}, plans: {}, imports: [], snapshots: [] }
}

// Tombstones keep a project deleted offline from coming back on the next sync.
const TOMB = 'vault-health.tombstones'
export const tombstones = (): string[] => { try { return JSON.parse(localStorage.getItem(TOMB) ?? '[]') } catch { return [] } }
const addTombstone = (id: string) => localStorage.setItem(TOMB, JSON.stringify([...new Set([...tombstones(), id])]))
const removeTombstone = (id: string) => localStorage.setItem(TOMB, JSON.stringify(tombstones().filter(x => x !== id)))
export const clearTombstones = (ids: string[]) => localStorage.setItem(TOMB, JSON.stringify(tombstones().filter(x => !ids.includes(x))))

// ---------- Settings ----------

export interface Prefs { breachCheck: boolean; tfaLive: boolean; genLength: number; autoClear: boolean }
const PREF_KEY = 'vault-health.prefs'
const DEF: Prefs = { breachCheck: true, tfaLive: true, genLength: 24, autoClear: false }
export function getPrefs(): Prefs { try { return { ...DEF, ...JSON.parse(localStorage.getItem(PREF_KEY) ?? '{}') } } catch { return DEF } }
export const setPrefs = (p: Prefs) => localStorage.setItem(PREF_KEY, JSON.stringify(p))
