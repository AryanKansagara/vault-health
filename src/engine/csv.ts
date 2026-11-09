/** RFC 4180 CSV parser: quoted fields, escaped quotes, CRLF, newlines inside quotes. Returns rows with their 1-based start line. */
export function parseCsv(text: string): { cells: string[]; line: number }[] {
  const out: { cells: string[]; line: number }[] = []
  let row: string[] = []
  let field = ''
  let quoted = false
  let line = 1
  let rowLine = 1
  const src = text.charCodeAt(0) === 0xfeff ? text.slice(1) : text
  for (let i = 0; i < src.length; i++) {
    const c = src[i]
    if (quoted) {
      if (c === '"') {
        if (src[i + 1] === '"') { field += '"'; i++ } else quoted = false
      } else {
        if (c === '\n') line++
        field += c
      }
      continue
    }
    if (c === '"') quoted = true
    else if (c === ',') { row.push(field); field = '' }
    else if (c === '\n' || c === '\r') {
      if (c === '\r' && src[i + 1] === '\n') i++
      row.push(field); field = ''
      if (row.length > 1 || row[0] !== '') out.push({ cells: row, line: rowLine })
      row = []
      line++
      rowLine = line
    } else field += c
  }
  row.push(field)
  if (row.length > 1 || row[0] !== '') out.push({ cells: row, line: rowLine })
  return out
}

const esc = (v: string | number | boolean | null | undefined) => {
  const s = v == null ? '' : String(v)
  // Neutralise spreadsheet formula injection from item titles.
  const safe = /^[=+\-@\t\r]/.test(s) ? `'${s}` : s
  return /[",\n\r]/.test(safe) ? `"${safe.replace(/"/g, '""')}"` : safe
}
export const toCsv = (rows: (string | number | boolean | null | undefined)[][]) => rows.map(r => r.map(esc).join(',')).join('\r\n') + '\r\n'
