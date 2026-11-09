// Network checks and the in-memory import. Nothing in this file writes to storage.
import { parseRange, sha1 } from './engine/analyze.ts'
import { TFA_FALLBACK, tfaDomains } from './engine/domain.ts'
import type { RawItem } from './engine/formats.ts'

export const HIBP_URL = 'https://api.pwnedpasswords.com/range/'
export const TFA_URL = 'https://api.2fa.directory/v3/totp.json'

/**
 * Have I Been Pwned k-anonymity check. Only the first 5 hex characters of each SHA-1 leave the browser,
 * with Add-Padding so the response size does not hint at the result.
 */
export async function checkBreaches(passwords: string[], onProgress?: (done: number, total: number) => void): Promise<{ map: Map<string, boolean>; failed: number }> {
  const hashes = [...new Set(await Promise.all([...new Set(passwords)].map(sha1)))]
  const byPrefix = new Map<string, string[]>()
  for (const h of hashes) (byPrefix.get(h.slice(0, 5)) ?? byPrefix.set(h.slice(0, 5), []).get(h.slice(0, 5))!).push(h)
  const prefixes = [...byPrefix.keys()]
  const map = new Map<string, boolean>()
  let done = 0, failed = 0
  const worker = async () => {
    for (let p = prefixes.pop(); p; p = prefixes.pop()) {
      try {
        const r = await fetch(HIBP_URL + p, { headers: { 'Add-Padding': 'true' } })
        if (!r.ok) throw new Error(String(r.status))
        const hits = parseRange(p, await r.text())
        for (const h of byPrefix.get(p)!) map.set(h, hits.has(h))
      } catch { failed += byPrefix.get(p)!.length }
      onProgress?.(++done, byPrefix.size)
    }
  }
  await Promise.all(Array.from({ length: 6 }, worker))
  return { map, failed }
}

let tfaCache: Promise<{ set: Set<string>; live: boolean }> | null = null
/** 2fa.directory TOTP list (CORS-enabled). Falls back to a bundled slice if it cannot be reached. */
export function tfaSet(live = true): Promise<{ set: Set<string>; live: boolean }> {
  if (!live) return Promise.resolve({ set: new Set(TFA_FALLBACK), live: false })
  return tfaCache ??= fetch(TFA_URL).then(r => r.ok ? r.json() : Promise.reject(new Error(String(r.status)))).then(j => {
    const set = tfaDomains(j)
    if (set.size < 100) throw new Error('unexpected dataset')
    return { set, live: true }
  }).catch(() => { tfaCache = null; return { set: new Set(TFA_FALLBACK), live: false } })
}

let zx: Promise<(pw: string) => number> | null = null
/** zxcvbn-ts with the common dictionaries, loaded only when a real import runs. */
export function strengthScorer(): Promise<(pw: string) => number> {
  return zx ??= Promise.all([import('@zxcvbn-ts/core'), import('@zxcvbn-ts/language-common')]).then(([core, common]) => {
    const factory = new core.ZxcvbnFactory({ dictionary: common.dictionary, graphs: common.adjacencyGraphs })
    return (pw: string) => factory.check(pw.slice(0, 100)).score
  })
}

// ---------- The imported file, in memory only ----------

let held: { projectId: string; fileName: string; items: RawItem[] } | null = null
const subs = new Set<() => void>()
export const holdImport = (projectId: string, fileName: string, items: RawItem[]) => { held = { projectId, fileName, items }; subs.forEach(f => f()) }
export const heldImport = () => held
export const subscribeHeld = (f: () => void) => { subs.add(f); return () => { subs.delete(f) } }

/** Drops every reference to the parsed passwords. Strings are immutable in JS, so this is as far as a web page can go; the garbage collector reclaims them. */
export function clearImport() {
  if (held) for (const it of held.items) { it.password = ''; it.username = '' }
  held = null
  subs.forEach(f => f())
}
