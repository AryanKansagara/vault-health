export const SETS = {
  lower: 'abcdefghijkmnopqrstuvwxyz',
  upper: 'ABCDEFGHJKLMNPQRSTUVWXYZ',
  digits: '23456789',
  symbols: '!#$%&*+-=?@^_~',
}

/** Unbiased random index in [0, n) via rejection sampling on crypto.getRandomValues. */
function randInt(n: number): number {
  const lim = Math.floor(0x100000000 / n) * n
  const b = new Uint32Array(1)
  do crypto.getRandomValues(b); while (b[0] >= lim)
  return b[0] % n
}

/** A password with at least one character from each chosen set. Look-alikes (l, 1, O, 0, I) are left out. Never stored. */
export function generate(length = 24, use: (keyof typeof SETS)[] = ['lower', 'upper', 'digits', 'symbols']): string {
  const sets = use.map(k => SETS[k])
  const all = sets.join('')
  const n = Math.max(length, sets.length)
  const out = sets.map(s => s[randInt(s.length)])
  while (out.length < n) out.push(all[randInt(all.length)])
  for (let i = out.length - 1; i > 0; i--) { const j = randInt(i + 1); [out[i], out[j]] = [out[j], out[i]] }
  return out.join('')
}

export const entropyBits = (length: number, use: (keyof typeof SETS)[]) => Math.round(length * Math.log2(use.reduce((a, k) => a + SETS[k].length, 0)))
