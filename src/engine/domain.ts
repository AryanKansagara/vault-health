const TWO_LEVEL = new Set(['co.uk', 'org.uk', 'ac.uk', 'gov.uk', 'com.au', 'net.au', 'org.au', 'co.nz', 'co.jp', 'com.br', 'co.in', 'com.mx', 'co.za', 'com.sg', 'com.cn'])

/** Registrable domain of a URL-ish string ("https://app.www.example.co.uk/x" -> "example.co.uk"). Empty when there is none. */
export function domainOf(raw: string): string {
  const s = raw.trim()
  if (!s) return ''
  let host = ''
  try { host = new URL(/^[a-z][a-z0-9+.-]*:\/\//i.test(s) ? s : `https://${s}`).hostname } catch { return '' }
  host = host.toLowerCase().replace(/\.$/, '')
  if (!host.includes('.') || /^\d+\.\d+\.\d+\.\d+$/.test(host) || host.startsWith('[')) return host
  const parts = host.split('.')
  const last2 = parts.slice(-2).join('.')
  return TWO_LEVEL.has(last2) && parts.length > 2 ? parts.slice(-3).join('.') : last2
}

/** Apps that commonly offer SAML/OIDC single sign-on (often on a paid tier). A rotation step on one of these is a chance to move it behind SSO instead. */
export const SSO_APPS = new Set([
  'google.com', 'microsoft.com', 'office.com', 'live.com', 'slack.com', 'github.com', 'gitlab.com', 'atlassian.com', 'atlassian.net', 'salesforce.com',
  'zoom.us', 'dropbox.com', 'box.com', 'notion.so', 'figma.com', 'hubspot.com', 'aws.amazon.com', 'amazon.com', 'okta.com', 'asana.com', 'monday.com',
  'miro.com', 'zendesk.com', 'intercom.com', 'docusign.com', 'adobe.com', 'canva.com', 'airtable.com', 'linear.app', 'datadoghq.com', 'cloudflare.com',
  'digitalocean.com', 'vercel.com', 'quickbooks.com', 'intuit.com', 'xero.com', 'gusto.com', 'rippling.com', 'bamboohr.com', 'workday.com', 'mailchimp.com',
  'loom.com', 'clickup.com', 'trello.com', 'smartsheet.com', 'freshdesk.com', 'sentry.io', 'heroku.com', 'webex.com', 'expensify.com', 'brex.com', 'ramp.com',
])

/** A small built-in slice of 2fa.directory (TOTP-capable sites), used when the live dataset cannot be fetched. */
export const TFA_FALLBACK = [
  'google.com', 'microsoft.com', 'live.com', 'apple.com', 'amazon.com', 'facebook.com', 'instagram.com', 'x.com', 'twitter.com', 'linkedin.com', 'tiktok.com',
  'pinterest.com', 'github.com', 'gitlab.com', 'slack.com', 'dropbox.com', 'box.com', 'zoom.us', 'atlassian.com', 'salesforce.com', 'hubspot.com', 'mailchimp.com',
  'notion.so', 'figma.com', 'canva.com', 'adobe.com', 'shopify.com', 'stripe.com', 'paypal.com', 'quickbooks.com', 'intuit.com', 'xero.com', 'gusto.com',
  'godaddy.com', 'namecheap.com', 'cloudflare.com', 'digitalocean.com', 'heroku.com', 'wordpress.com', 'squarespace.com', 'wix.com', 'bitly.com', 'hootsuite.com',
  'buffer.com', 'reddit.com', 'twitch.tv', 'discord.com', 'zendesk.com', 'docusign.com', 'asana.com', 'trello.com', 'miro.com', 'airtable.com', 'mailgun.com',
  'sendgrid.com', 'twilio.com', 'okta.com', 'aws.amazon.com', 'bankofamerica.com', 'chase.com', 'wellsfargo.com', 'americanexpress.com', 'coinbase.com',
  'ebay.com', 'etsy.com', 'yahoo.com', 'proton.me', 'fastmail.com', 'zoho.com', 'vimeo.com', 'youtube.com', 'snapchat.com', 'behance.net', 'dribbble.com',
  'expensify.com', 'brex.com', 'ramp.com', 'rippling.com', 'bamboohr.com', 'clickup.com', 'monday.com', 'loom.com', 'sentry.io', 'vercel.com', 'linear.app',
]

/** Checks a domain and its parents against a set of 2FA-capable domains. */
export function supportsTfa(domain: string, set: Set<string>): boolean {
  if (!domain) return false
  const parts = domain.split('.')
  for (let i = 0; i < parts.length - 1; i++) if (set.has(parts.slice(i).join('.'))) return true
  return false
}

export function isSso(domain: string): boolean {
  return supportsTfa(domain, SSO_APPS)
}

/** Parses the 2fa.directory v3 totp.json shape: [[name, { domain, "additional-domains"?: [] }], ...]. */
export function tfaDomains(json: unknown): Set<string> {
  const out = new Set<string>()
  if (!Array.isArray(json)) return out
  for (const e of json) {
    const v = Array.isArray(e) ? e[1] : null
    if (!v || typeof v !== 'object') continue
    const o = v as { domain?: string; 'additional-domains'?: string[] }
    if (o.domain) out.add(o.domain.toLowerCase())
    for (const d of o['additional-domains'] ?? []) out.add(d.toLowerCase())
  }
  return out
}
