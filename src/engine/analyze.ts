import { domainOf, isSso, supportsTfa } from './domain.ts'
import type { RawItem } from './formats.ts'

/**
 * The only thing that is ever stored or synced. No password, no username, no hash a password can be tested against:
 * reuse ids are 32-bit truncations of a salted hash whose salt is thrown away after the import.
 */
export interface Finding {
  id: string
  title: string
  domain: string
  vault: string
  /** 0 (guessable in seconds) to 4 (very strong), zxcvbn scale. */
  strength: number
  /** Exact-reuse group, null when the password is unique. */
  group: string | null
  /** Near-reuse group (same password with digits/symbols changed, e.g. Summer2024! / Summer2025!), null when none. */
  near: string | null
  /** Seen in a breach per Have I Been Pwned. null = not checked. */
  breached: boolean | null
  /** ISO date of the last password change, null if the export has none. */
  changed: string | null
  /** The site supports TOTP two-factor (2fa.directory). */
  tfa: boolean
  /** A TOTP secret is stored with the item. */
  totp: boolean
  shared: boolean
  /** Site commonly supports SSO, so it could leave the shared-password list entirely. */
  sso: boolean
}

const hex = (b: ArrayBuffer) => [...new Uint8Array(b)].map(x => x.toString(16).padStart(2, '0')).join('')
export const sha1 = async (s: string) => hex(await crypto.subtle.digest('SHA-1', new TextEncoder().encode(s))).toUpperCase()
const sha256 = async (s: string) => hex(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(s)))

/** Letters-only skeleton: "Summer2024!" and "summer-2025" both become "summer". */
export function skeleton(pw: string): string {
  return pw.replace(/^[^a-zA-Z]+|[^a-zA-Z]+$/g, '').toLowerCase().replace(/[@4]/g, 'a').replace(/3/g, 'e').replace(/[$5]/g, 's').replace(/0/g, 'o').replace(/[^a-z]/g, '')
}

/**
 * Dependency-free strength estimate on the zxcvbn 0-4 scale, used for the synthetic samples, the hero and as a fallback.
 * It is deliberately conservative: dictionary-ish words with a year or symbol tacked on score low.
 */
const COMMON = ['password', 'welcome', 'summer', 'winter', 'spring', 'autumn', 'fall', 'letmein', 'qwerty', 'admin', 'login', 'monkey', 'dragon', 'iloveyou', 'abc', 'company', 'changeme', 'secret', 'master', 'football', 'baseball', 'sunshine', 'princess', 'office', 'social', 'test']
export function quickScore(pw: string): number {
  if (pw.length < 6) return 0
  const sk = skeleton(pw)
  const pools = [/[a-z]/, /[A-Z]/, /\d/, /[^a-zA-Z0-9]/].filter(r => r.test(pw)).length
  const uniq = new Set(pw).size
  let bits = pw.length * Math.log2([0, 26, 52, 62, 94][pools])
  if (COMMON.some(w => sk.includes(w))) bits = Math.min(bits, 28 + Math.max(0, sk.length - 8) * 2)
  if (/(19|20)\d\d/.test(pw)) bits -= 8
  if (/^[A-Z][a-z]+[\d!@#$%^&*.]+$/.test(pw)) bits = Math.min(bits, 34)
  if (uniq < pw.length / 2) bits -= 10
  return bits < 28 ? 0 : bits < 40 ? 1 : bits < 60 ? 2 : bits < 80 ? 3 : 4
}

export interface AnalyzeOptions {
  /** 0-4 strength for a password. Defaults to quickScore. */
  score?: (pw: string) => number
  /** SHA-1 (upper hex) -> breached. Missing hashes count as unchecked. */
  breached?: Map<string, boolean>
  tfa?: Set<string>
}

export async function analyze(items: RawItem[], opts: AnalyzeOptions = {}): Promise<Finding[]> {
  const score = opts.score ?? quickScore
  const salt = crypto.getRandomValues(new Uint8Array(16)).join('.')
  const exact = new Map<string, number>()
  const nearPw = new Map<string, Set<string>>()
  for (const it of items) {
    exact.set(it.password, (exact.get(it.password) ?? 0) + 1)
    const sk = skeleton(it.password)
    if (sk.length >= 4) (nearPw.get(sk) ?? nearPw.set(sk, new Set()).get(sk)!).add(it.password)
  }
  const out: Finding[] = []
  const seen = new Map<string, number>()
  const scoreCache = new Map<string, number>()
  for (const it of items) {
    const domain = domainOf(it.url)
    let id = (await sha256(`${it.vault}|${it.title}|${domain}|${it.username}`)).slice(0, 12)
    const dup = seen.get(id) ?? 0
    seen.set(id, dup + 1)
    if (dup) id += `-${dup}`
    const sk = skeleton(it.password)
    const nearSet = sk.length >= 4 ? nearPw.get(sk)! : null
    const s = scoreCache.get(it.password) ?? score(it.password)
    scoreCache.set(it.password, s)
    const h = opts.breached ? await sha1(it.password) : ''
    out.push({
      id,
      title: it.title,
      domain,
      vault: it.vault,
      strength: s,
      group: exact.get(it.password)! > 1 ? (await sha256(salt + it.password)).slice(0, 8) : null,
      near: nearSet && nearSet.size > 1 ? (await sha256(salt + '~' + sk)).slice(0, 8) : null,
      breached: opts.breached?.has(h) ? opts.breached.get(h)! : null,
      changed: it.changed,
      tfa: opts.tfa ? supportsTfa(domain, opts.tfa) : false,
      totp: it.totp,
      shared: it.shared,
      sso: isSso(domain),
    })
  }
  return out
}

/** Parses an HIBP range response. Padded lines have a count of 0 and are ignored. */
export function parseRange(prefix: string, body: string): Set<string> {
  const out = new Set<string>()
  for (const line of body.split(/\r?\n/)) {
    const [suffix, count] = line.trim().split(':')
    if (suffix && Number(count) > 0) out.add(prefix.toUpperCase() + suffix.toUpperCase())
  }
  return out
}
