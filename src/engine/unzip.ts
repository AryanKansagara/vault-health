/** Reads one file out of a zip archive (stored or deflated) using the platform DecompressionStream. Enough for .1pux. */
export async function readZipEntry(buf: ArrayBuffer, name: string): Promise<Uint8Array | null> {
  const v = new DataView(buf)
  let eocd = -1
  for (let i = buf.byteLength - 22; i >= Math.max(0, buf.byteLength - 65557); i--) if (v.getUint32(i, true) === 0x06054b50) { eocd = i; break }
  if (eocd < 0) throw new Error('Not a zip archive.')
  const count = v.getUint16(eocd + 10, true)
  let p = v.getUint32(eocd + 16, true)
  const dec = new TextDecoder()
  for (let k = 0; k < count; k++) {
    if (v.getUint32(p, true) !== 0x02014b50) throw new Error('Corrupt zip directory.')
    const method = v.getUint16(p + 10, true)
    const size = v.getUint32(p + 20, true)
    const nlen = v.getUint16(p + 28, true), xlen = v.getUint16(p + 30, true), clen = v.getUint16(p + 32, true)
    const local = v.getUint32(p + 42, true)
    const fname = dec.decode(new Uint8Array(buf, p + 46, nlen))
    p += 46 + nlen + xlen + clen
    if (fname !== name) continue
    const start = local + 30 + v.getUint16(local + 26, true) + v.getUint16(local + 28, true)
    const data = new Uint8Array(buf, start, size)
    if (method === 0) return data
    if (method !== 8) throw new Error(`Unsupported zip compression (${method}).`)
    const stream = new Blob([data]).stream().pipeThrough(new DecompressionStream('deflate-raw'))
    return new Uint8Array(await new Response(stream).arrayBuffer())
  }
  return null
}
