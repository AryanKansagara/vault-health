// Synthetic vaults. Every person, company and password here is made up. The "breached" passwords are
// well-known dictionary passwords (the kind every breach corpus contains), not credentials from anywhere real.
import { sha1 } from './analyze.ts'
import { toCsv } from './csv.ts'
import type { RawItem } from './formats.ts'

export interface SampleDef { id: string; name: string; blurb: string; people: number; departing: string }

/** Passwords the samples treat as breached. All are classic, public dictionary passwords. */
export const SAMPLE_BREACHED = new Set(['Summer2024!', 'Welcome123!', 'Password1', 'Harbor2020!', 'Qwerty123!', 'letmein1', 'Spring2023!', 'Freight2019'])

function rng(seed: number) {
  return () => { seed |= 0; seed = (seed + 0x6d2b79f5) | 0; let t = Math.imul(seed ^ (seed >>> 15), 1 | seed); t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t; return ((t ^ (t >>> 14)) >>> 0) / 4294967296 }
}
const strong = (r: () => number, n = 20) => { const c = 'abcdefghjkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789!#%&*+-?@'; let s = ''; for (let i = 0; i < n; i++) s += c[Math.floor(r() * c.length)]; return s }

// [vault, title, url, password ('*' = generated strong), changed, totp, previous password ('*' = was strong too, omitted = same)]
type Row = [string, string, string, string, string, boolean, string?]

interface Def extends SampleDef { seed: number; rows: Row[]; vaults: Record<string, string[] | 'all'>; owners: Record<string, string>; staff: string[] }

const AGENCY_STAFF = ['Avery Chen', 'Jordan Lee', 'Priya Natarajan', 'Marcus Webb', 'Sofia Alvarez', 'Ethan Brooks', 'Hana Sato', 'Liam O’Connor', 'Zoe Martin', 'Daniel Kim', 'Grace Okafor', 'Noah Fischer', 'Isla Murray', 'Mateo Rossi', 'Chloe Dubois', 'Owen Patel', 'Maya Johansson', 'Lucas Silva', 'Ruby Thompson', 'Ari Cohen', 'Nina Kowalski', 'Theo Grant', 'Leila Haddad', 'Sam Rivera', 'Ivy Nguyen']

const SOCIAL = 'NwSocial#2021'
const AGENCY: Def = {
  id: 'agency', name: 'Northwind Creative', blurb: '25-person agency. One social login reused across six sites, a departing account lead.', people: 25, departing: 'Jordan Lee', seed: 7,
  staff: AGENCY_STAFF,
  vaults: { 'Marketing & Social': ['Avery Chen', 'Jordan Lee', 'Sofia Alvarez', 'Hana Sato', 'Zoe Martin', 'Chloe Dubois', 'Maya Johansson', 'Ruby Thompson'], 'Ops & Finance': ['Avery Chen', 'Marcus Webb', 'Grace Okafor', 'Leila Haddad'], Engineering: ['Daniel Kim', 'Noah Fischer', 'Owen Patel', 'Lucas Silva', 'Jordan Lee', 'Theo Grant'], Everyone: 'all', Leadership: ['Avery Chen', 'Marcus Webb', 'Priya Natarajan'] },
  owners: { 'Marketing & Social': 'Sofia Alvarez', 'Ops & Finance': 'Marcus Webb', Engineering: 'Daniel Kim', Everyone: 'Avery Chen', Leadership: 'Avery Chen' },
  rows: [
    ['Marketing & Social', 'Instagram (brand)', 'https://www.instagram.com', SOCIAL, '2021-05-14', false],
    ['Marketing & Social', 'Facebook Page admin', 'https://facebook.com', SOCIAL, '2021-05-14', false],
    ['Marketing & Social', 'X / Twitter', 'https://x.com', SOCIAL, '2021-05-14', false],
    ['Marketing & Social', 'LinkedIn company page', 'https://www.linkedin.com', SOCIAL, '2021-06-02', false],
    ['Marketing & Social', 'TikTok', 'https://www.tiktok.com', SOCIAL, '2022-01-20', false],
    ['Marketing & Social', 'Pinterest', 'https://pinterest.com', SOCIAL, '2022-01-20', false],
    ['Marketing & Social', 'Mailchimp', 'https://login.mailchimp.com', 'Summer2024!', '2024-06-03', false],
    ['Marketing & Social', 'Hootsuite', 'https://hootsuite.com', 'Summer2025!', '2025-06-11', false],
    ['Marketing & Social', 'Canva Teams', 'https://www.canva.com', '*', '2025-09-12', true],
    ['Marketing & Social', 'Later.com scheduler', 'https://later.com', '*', '2025-10-20', false, 'Summer2023!'],
    ['Marketing & Social', 'Bitly', 'https://bitly.com', '*', '2024-02-19', false],
    ['Ops & Finance', 'QuickBooks Online', 'https://quickbooks.intuit.com', '*', '2025-03-30', true],
    ['Ops & Finance', 'Gusto payroll', 'https://app.gusto.com', '*', '2025-08-14', true],
    ['Ops & Finance', 'Chase business banking', 'https://chase.com', 'Northwind!2020', '2020-11-09', false],
    ['Ops & Finance', 'Expensify', 'https://www.expensify.com', '*', '2025-01-22', false],
    ['Ops & Finance', 'Office supplies portal', 'https://www.staples.com', 'Welcome123!', '2022-04-18', false],
    ['Ops & Finance', 'DocuSign', 'https://docusign.com', '*', '2025-10-01', true],
    ['Engineering', 'GoDaddy (domains)', 'https://sso.godaddy.com', 'Qwerty123!', '2021-02-02', false],
    ['Engineering', 'Cloudflare', 'https://dash.cloudflare.com', '*', '2025-04-08', true],
    ['Engineering', 'GitHub org owner', 'https://github.com', '*', '2025-07-21', true],
    ['Engineering', 'WP Engine', 'https://my.wpengine.com', 'Northwind!2021', '2021-08-30', false],
    ['Engineering', 'Client staging WordPress', 'https://staging.acme-client.example', 'Northwind!2021', '2021-08-30', false],
    ['Engineering', 'Vercel', 'https://vercel.com', '*', '2025-09-30', true],
    ['Engineering', 'AWS root (legacy)', 'https://aws.amazon.com', '*', '2025-10-28', true, 'Welcome123!'],
    ['Everyone', 'Office Wi-Fi router admin', 'http://192.168.1.1', 'Password1', '2019-09-01', false],
    ['Everyone', 'Printer / scanner portal', 'http://10.0.0.20', 'letmein1', '2020-03-15', false],
    ['Everyone', 'Zoom (shared room)', 'https://zoom.us', '*', '2025-05-05', false],
    ['Everyone', 'Slack workspace admin', 'https://northwind.slack.com', '*', '2025-02-27', true],
    ['Everyone', 'Adobe Creative Cloud (team seat)', 'https://adobe.com', 'Spring2023!', '2023-03-20', false],
    ['Everyone', 'Figma (shared editor)', 'https://figma.com', '*', '2024-12-01', false],
    ['Everyone', 'Shutterstock', 'https://www.shutterstock.com', 'Northwind!2022', '2022-05-10', false],
    ['Leadership', 'Google Workspace super admin', 'https://admin.google.com', '*', '2025-06-30', true],
    ['Leadership', 'Cyber insurance portal', 'https://portal.coalitioninc.com', '*', '2025-01-15', false],
    ['Leadership', 'HubSpot (sales)', 'https://app.hubspot.com', '*', '2024-10-10', true],
    ['Leadership', 'Investor data room', 'https://www.dropbox.com', '*', '2025-08-01', true],
  ],
}

const DENTAL: Def = {
  id: 'dental', name: 'Harbor Family Dental', blurb: '14-person clinic. Insurance portals on near-identical passwords, front desk turnover.', people: 14, departing: 'Kayla Brooks', seed: 21,
  staff: ['Dr. Elena Park', 'Dr. James Holt', 'Kayla Brooks', 'Rosa Medina', 'Tyler Nash', 'Bea Hughes', 'Imani Wright', 'Colin Shaw', 'Mia Laurent', 'Jun Tanaka', 'Paula Reyes', 'Ben Adler', 'Nora Quinn', 'Will Ashby'],
  vaults: { 'Front Desk': ['Kayla Brooks', 'Rosa Medina', 'Tyler Nash', 'Bea Hughes', 'Paula Reyes'], Billing: ['Kayla Brooks', 'Imani Wright', 'Dr. Elena Park'], Clinical: ['Dr. Elena Park', 'Dr. James Holt', 'Colin Shaw', 'Mia Laurent', 'Jun Tanaka', 'Ben Adler'], Everyone: 'all' },
  owners: { 'Front Desk': 'Rosa Medina', Billing: 'Imani Wright', Clinical: 'Dr. James Holt', Everyone: 'Dr. Elena Park' },
  rows: [
    ['Billing', 'Delta Dental provider portal', 'https://www.deltadentalins.com', 'Harbor2020!', '2020-08-12', false],
    ['Billing', 'MetLife dental claims', 'https://www.metlife.com', 'Harbor2022!', '2022-02-03', false],
    ['Billing', 'Cigna for HCP', 'https://cignaforhcp.cigna.com', 'Harbor2023!', '2023-01-09', false, 'Harbor2020!'],
    ['Billing', 'Clearinghouse (claims)', 'https://www.dentalxchange.com', '*', '2025-02-14', false],
    ['Billing', 'Square payments', 'https://squareup.com', '*', '2025-06-20', true],
    ['Front Desk', 'Practice management (cloud)', 'https://app.dentrix.example', '*', '2025-09-02', false],
    ['Front Desk', 'Appointment reminders', 'https://www.weave.com', 'FrontDesk1', '2021-04-04', false],
    ['Front Desk', 'Google Business Profile', 'https://business.google.com', 'FrontDesk1', '2021-04-04', false],
    ['Front Desk', 'Facebook page', 'https://facebook.com', 'FrontDesk2', '2022-11-30', false],
    ['Front Desk', 'Yelp for Business', 'https://biz.yelp.com', '*', '2024-04-01', false],
    ['Clinical', 'Imaging software license', 'https://portal.imaging.example', '*', '2023-05-05', false],
    ['Clinical', 'Lab case portal', 'https://www.glidewelldental.com', '*', '2025-03-13', false],
    ['Clinical', 'Supply ordering', 'https://www.henryschein.com', 'Qwerty123!', '2021-10-10', false],
    ['Everyone', 'Microsoft 365 shared mailbox', 'https://outlook.office.com', '*', '2025-07-07', true],
    ['Everyone', 'Clinic Wi-Fi admin', 'http://192.168.0.1', 'Password1', '2018-12-01', false],
    ['Everyone', 'Door access system', 'https://access.kisi.example', '*', '2024-09-09', false],
  ],
}

const FREIGHT: Def = {
  id: 'freight', name: 'Ridgeline Freight', blurb: '60-person logistics firm in decent shape. A few legacy carrier portals and one old admin.', people: 60, departing: 'Victor Hale', seed: 99,
  staff: ['Victor Hale', 'Dana Price', 'Ken Mori', 'Alicia Grant', 'Ravi Shah', 'Beth Collins', 'Omar Diaz', 'Tess Young', 'Hugo Lambert', 'Femi Ade'],
  vaults: { 'IT Admin': ['Victor Hale', 'Ken Mori', 'Ravi Shah'], Dispatch: ['Dana Price', 'Omar Diaz', 'Tess Young', 'Victor Hale', 'Femi Ade'], Finance: ['Alicia Grant', 'Beth Collins', 'Hugo Lambert'], Everyone: 'all' },
  owners: { 'IT Admin': 'Ken Mori', Dispatch: 'Dana Price', Finance: 'Alicia Grant', Everyone: 'Ken Mori' },
  rows: [
    ['IT Admin', 'Microsoft 365 global admin', 'https://admin.microsoft.com', '*', '2025-08-08', true],
    ['IT Admin', 'Firewall admin', 'https://fw.ridgeline.example', '*', '2024-01-17', false],
    ['IT Admin', 'Domain registrar', 'https://www.namecheap.com', 'Freight2019', '2019-06-06', false],
    ['IT Admin', 'Backup console', 'https://backup.example', '*', '2025-05-05', true],
    ['IT Admin', 'AWS (TMS hosting)', 'https://aws.amazon.com', '*', '2025-09-19', true],
    ['IT Admin', 'Okta admin', 'https://ridgeline.okta.com', '*', '2025-10-02', true, 'Qwerty123!'],
    ['Dispatch', 'DAT load board', 'https://www.dat.com', '*', '2025-04-22', false],
    ['Dispatch', 'Carrier portal A', 'https://carrier-a.example', 'Ridgeline#Disp1', '2022-03-03', false],
    ['Dispatch', 'Carrier portal B', 'https://carrier-b.example', 'Ridgeline#Disp2', '2023-03-03', false],
    ['Dispatch', 'ELD fleet dashboard', 'https://cloud.samsara.com', '*', '2025-02-02', true],
    ['Dispatch', 'Fuel card portal', 'https://www.wexinc.com', '*', '2024-11-11', false],
    ['Finance', 'Bank of America CashPro', 'https://bankofamerica.com', '*', '2025-07-01', true],
    ['Finance', 'Xero', 'https://xero.com', '*', '2025-06-15', true],
    ['Finance', 'Factoring portal', 'https://portal.factoring.example', '*', '2024-12-20', false],
    ['Everyone', 'Guest Wi-Fi', 'http://10.10.0.1', '*', '2025-01-05', false],
    ['Everyone', 'Shared Zoom', 'https://zoom.us', '*', '2025-03-03', false],
  ],
}

export const SAMPLES: SampleDef[] = [AGENCY, DENTAL, FREIGHT].map(({ id, name, blurb, people, departing }) => ({ id, name, blurb, people, departing }))
const DEFS = { agency: AGENCY, dental: DENTAL, freight: FREIGHT } as Record<string, Def>

/** A sample as the files a user would import: a vault export CSV and an access-list CSV. `era: 'before'` is the same vault one quarter earlier. */
export function sampleFiles(id: string, era: 'now' | 'before' = 'now', now = new Date()): { vault: string; access: string } {
  const d = DEFS[id]
  // Dates are written as of late 2025; shift them so the sample always looks current.
  const years = Math.max(0, now.getUTCFullYear() - 2025 - (now.getUTCMonth() < 10 ? 1 : 0))
  const shift = (iso: string) => `${Number(iso.slice(0, 4)) + years}${iso.slice(4)}`
  const r = rng(d.seed)
  const vault: (string | boolean)[][] = [['vault', 'title', 'url', 'username', 'password', 'totp', 'last_changed']]
  for (const [v, title, url, pw, changed, totp, was] of d.rows) {
    const cur = pw === '*' ? strong(r) : pw
    const old = was === undefined ? cur : was === '*' ? strong(r) : was
    const before = era === 'before' && was !== undefined
    vault.push([v, title, url, `${title.split(' ')[0].toLowerCase()}@${d.id}.example`, before ? old : cur, totp ? 'otpauth://totp/synthetic?secret=JBSWY3DPEHPK3PXP' : '', shift(before ? '2021-01-01' : changed)])
  }
  const access: string[][] = [['person', 'vault', 'role']]
  for (const [v, who] of Object.entries(d.vaults)) for (const p of who === 'all' ? d.staff : who) access.push([p, v, d.owners[v] === p ? 'owner' : 'member'])
  return { vault: toCsv(vault), access: toCsv(access) }
}

export async function sampleBreaches(items: RawItem[]): Promise<Map<string, boolean>> {
  const m = new Map<string, boolean>()
  for (const it of items) m.set(await sha1(it.password), SAMPLE_BREACHED.has(it.password))
  return m
}
