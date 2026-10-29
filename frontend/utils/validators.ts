// Client-side checks that mirror the backend rules that never depend on operator settings (TRD "Skema data" and "Keamanan").
// They only give early feedback; the server validates again and stays authoritative.

export const PRIVATE_NETWORK_MESSAGE = 'Private network addresses are not allowed.'

/**
 * True for host literals that are refused whatever the operator setting is: cloud metadata and
 * service endpoints (169.254.169.0/24, 169.254.170.0/24, 100.100.100.200, fd00:ec2::/32),
 * unspecified, multicast and reserved ranges. Private networks (loopback, RFC 1918, CGNAT, ULA,
 * link-local) are NOT checked here: the backend allows them unless the operator turns them off
 * (SDRSCAN_ALLOW_PRIVATE_NETWORKS=false), and the browser cannot know that, so the server decides.
 */
export function isAlwaysBlockedHost(rawHost: string): boolean {
  let host = rawHost.trim().toLowerCase().replace(/^\[|\]$/g, '').replace(/\.$/, '')
  if (!host) return false
  if (host === 'metadata.google.internal' || host === 'metadata') return true
  const mapped = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/.exec(host)
  if (mapped) host = mapped[1]!
  const mappedHex = /^::ffff:([0-9a-f]{1,4}):([0-9a-f]{1,4})$/.exec(host)
  if (mappedHex) {
    const hi = Number.parseInt(mappedHex[1]!, 16)
    const lo = Number.parseInt(mappedHex[2]!, 16)
    host = `${hi >> 8}.${hi & 255}.${lo >> 8}.${lo & 255}`
  }
  const v4 = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(host)
  if (v4) {
    const [a, b, c, d] = [Number(v4[1]), Number(v4[2]), Number(v4[3]), Number(v4[4])]
    return a === 0 || (a === 169 && b === 254 && (c === 169 || c === 170)) || (a === 100 && b === 100 && c === 100 && d === 200)
      || (a === 192 && b === 0 && c === 0) || (a === 198 && (b === 18 || b === 19)) || a >= 224
  }
  if (host.includes(':')) {
    if (host === '::') return true
    const parts = host.split(':')
    if (parts[0] === 'fd00' && parts[1] === 'ec2') return true
    const first = parts[0] ?? ''
    const n = first === '' ? 0 : Number.parseInt(first, 16)
    if (Number.isNaN(n)) return false
    // ff00::/8 (multicast)
    return (n & 0xff00) === 0xff00
  }
  return false
}

/**
 * True for host literals in loopback, link-local, cloud metadata, RFC 1918, CGNAT, ULA and similar ranges.
 * Names are only checked for obvious cases (localhost); the server resolves DNS and checks the result, also after redirects.
 */
export function isPrivateHost(rawHost: string): boolean {
  let host = rawHost.trim().toLowerCase().replace(/^\[|\]$/g, '').replace(/\.$/, '')
  if (!host) return false
  if (host === 'localhost' || host.endsWith('.localhost') || host === 'metadata.google.internal' || host.endsWith('.internal')) return true
  const mapped = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/.exec(host)
  if (mapped) host = mapped[1]!
  // URL normalises ::ffff:127.0.0.1 to ::ffff:7f00:1
  const mappedHex = /^::ffff:([0-9a-f]{1,4}):([0-9a-f]{1,4})$/.exec(host)
  if (mappedHex) {
    const hi = Number.parseInt(mappedHex[1]!, 16)
    const lo = Number.parseInt(mappedHex[2]!, 16)
    host = `${hi >> 8}.${hi & 255}.${lo >> 8}.${lo & 255}`
  }
  const v4 = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(host)
  if (v4) {
    const [a, b] = [Number(v4[1]), Number(v4[2])]
    return a === 0 || a === 10 || a === 127 || (a === 100 && b >= 64 && b <= 127) || (a === 169 && b === 254)
      || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) || (a === 192 && b === 0 && Number(v4[3]) === 0) || (a === 198 && (b === 18 || b === 19)) || a >= 224
  }
  if (host.includes(':')) {
    if (host === '::' || host === '::1') return true
    const first = host.split(':')[0] ?? ''
    const n = first === '' ? 0 : Number.parseInt(first, 16)
    if (Number.isNaN(n)) return false
    // fc00::/7 (ULA), fe80::/10 (link-local)
    return (n & 0xfe00) === 0xfc00 || (n & 0xffc0) === 0xfe80
  }
  return false
}

export const BRANCH_RE = /^[A-Za-z0-9._/-]{1,200}$/

/** https://host/path, ssh://host/path or git@host:path. Rejects http://, git://, file://, ext::, local paths, userinfo passwords, and a leading "-". */
export function validateRepoUrl(value: string): string | null {
  const v = value.trim()
  if (!v) return 'Repository URL is required.'
  if (v.startsWith('-')) return 'Repository URL must not start with "-".'
  const scp = /^git@([A-Za-z0-9.-]+):[^\s]+$/.exec(v)
  if (scp) return isAlwaysBlockedHost(scp[1]!) ? PRIVATE_NETWORK_MESSAGE : null
  let u: URL
  try {
    u = new URL(v)
  } catch {
    return 'Use https://host/path, ssh://host/path or git@host:path.'
  }
  if (u.protocol !== 'https:' && u.protocol !== 'ssh:') return 'Only https://, ssh:// and git@host:path URLs are allowed.'
  if (u.password) return 'Do not put a password in the URL. Use the credential fields instead.'
  if (!u.hostname) return 'The URL needs a host.'
  if (isAlwaysBlockedHost(u.hostname)) return PRIVATE_NETWORK_MESSAGE
  return null
}

/** http(s)://host[:port]/prefix without userinfo and without query. */
export function validateBaseUrl(value: string): string | null {
  const v = value.trim()
  if (!v) return 'Base URL is required.'
  let u: URL
  try {
    u = new URL(v)
  } catch {
    return 'Enter a full URL such as https://shop.example.com.'
  }
  if (u.protocol !== 'https:' && u.protocol !== 'http:') return 'Only http:// and https:// URLs are allowed.'
  if (u.username || u.password) return 'The URL must not contain a username or password.'
  if (u.search || v.includes('?')) return 'The URL must not contain a query string.'
  if (u.hash) return 'The URL must not contain a fragment.'
  if (isAlwaysBlockedHost(u.hostname)) return PRIVATE_NETWORK_MESSAGE
  return null
}

export function validateBranch(value: string): string | null {
  const v = value.trim()
  if (!v) return null
  if (v.startsWith('-') || !BRANCH_RE.test(v)) return 'Branch may only contain letters, digits, ".", "_", "-" and "/" (max 200).'
  return null
}

/** Relative path with "/" separators; empty means the whole repository. */
export function validateSubdirectory(value: string): string | null {
  const v = value.trim()
  if (!v) return null
  if (v.startsWith('/') || /^[A-Za-z]:/.test(v)) return 'Use a path relative to the repository root.'
  if (v.includes('\\')) return 'Use "/" as the path separator.'
  if (v.split('/').some(seg => seg === '..')) return 'The path must not contain "..".'
  return null
}

export function validateName(value: string, what = 'Name'): string | null {
  const v = value.trim()
  if (v.length < 1) return `${what} is required.`
  if (v.length > 100) return `${what} must be at most 100 characters.`
  // eslint-disable-next-line no-control-regex
  if (/[\u0000-\u001f\u007f]/.test(v)) return `${what} must not contain control characters.`
  return null
}

export function validateUsername(value: string): string | null {
  if (!value) return 'Username is required.'
  return /^[A-Za-z0-9._-]{3,64}$/.test(value) ? null : 'Username must be 3 to 64 characters: letters, digits, ".", "_" or "-".'
}

export function validateNewPassword(value: string, username?: string, what = 'Password'): string | null {
  if (!value) return `${what} is required.`
  if (value.length < 12) return `${what} must be at least 12 characters.`
  if (value.length > 128) return `${what} must be at most 128 characters.`
  if (username && value.toLowerCase() === username.toLowerCase()) return `${what} must not be the same as the username.`
  return null
}
