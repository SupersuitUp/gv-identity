// @supersuit/gv-identity: the ONE verifier for the `gv_id` cookie, the single sign-in shared by every garysheng.com site.
//
// The cookie is a compact JWS, ES256 (P-256), payload exactly { email, iat, exp, aud }. One issuer holds the private
// key; every reader holds the public key and passes it in, with the audience it expects. The cookie says WHO, never
// what they may open: each site applies its own rule to the email this returns.
//
// Web Crypto only (globalThis.crypto.subtle, atob): it runs in Vercel Edge middleware and in Node 20+ alike.

export const GV_ID_COOKIE = 'gv_id'
export const GV_ID_AUDIENCE = 'garysheng.com'
export const GV_ID_SIGN_IN_URL = 'https://continent.garysheng.com/id/sign-in'
export const GV_ID_SIGN_OUT_URL = 'https://continent.garysheng.com/id/sign-out'

// A token issued "in the future" by a clock this far ahead is still accepted.
const CLOCK_SKEW_S = 60
const B64URL = /^[A-Za-z0-9_-]+$/

export type GvIdOptions = {
  // The audience this site accepts, for example GV_ID_AUDIENCE. A token for any other audience is refused.
  audience: string
  // The issuer's public key (P-256 JWK). Not a secret.
  publicKeyJwk: JsonWebKey
  // Milliseconds since the epoch; defaults to Date.now().
  now?: number
}

function b64urlToBytes(s: string) {
  const b64 = s.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - (s.length % 4)) % 4)
  const bin = atob(b64)
  const out = new Uint8Array(bin.length)
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i)
  return out
}

function b64urlToJson(s: string): unknown {
  return JSON.parse(new TextDecoder().decode(b64urlToBytes(s)))
}

const keyCache = new Map<string, Promise<CryptoKey>>()
function importPublic(jwk: JsonWebKey): Promise<CryptoKey> {
  const id = `${jwk.crv}:${jwk.x}:${jwk.y}`
  let k = keyCache.get(id)
  if (!k) {
    k = crypto.subtle.importKey('jwk', { kty: 'EC', crv: 'P-256', x: jwk.x, y: jwk.y }, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify'])
    keyCache.set(id, k)
    k.catch(() => keyCache.delete(id))
  }
  return k
}

// The verified, lowercased email for a genuine, unexpired gv_id meant for `audience`; else null. Never throws.
export async function verifyGvId(cookieValue: string | null | undefined, opts: GvIdOptions): Promise<{ email: string } | null> {
  try {
    if (typeof cookieValue !== 'string' || cookieValue.length > 4096) return null
    const parts = cookieValue.split('.')
    if (parts.length !== 3 || !parts.every(p => B64URL.test(p))) return null
    const [h, p, s] = parts

    const header = b64urlToJson(h) as { alg?: unknown; crit?: unknown } | null
    if (!header || typeof header !== 'object' || header.alg !== 'ES256' || header.crit !== undefined) return null

    const payload = b64urlToJson(p) as { email?: unknown; iat?: unknown; exp?: unknown; aud?: unknown } | null
    if (!payload || typeof payload !== 'object') return null
    const { email, iat, exp, aud } = payload
    if (typeof opts.audience !== 'string' || opts.audience === '' || aud !== opts.audience) return null
    if (typeof email !== 'string' || email !== email.trim().toLowerCase() || !/^[^@\s]+@[^@\s]+$/.test(email)) return null
    if (typeof exp !== 'number' || typeof iat !== 'number' || !Number.isFinite(exp) || !Number.isFinite(iat)) return null
    const nowS = (opts.now ?? Date.now()) / 1000
    if (exp <= nowS) return null
    if (iat > nowS + CLOCK_SKEW_S) return null

    const sig = b64urlToBytes(s)
    if (sig.length !== 64) return null
    const key = await importPublic(opts.publicKeyJwk)
    const ok = await crypto.subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, key, sig, new TextEncoder().encode(`${h}.${p}`))
    return ok ? { email } : null
  } catch {
    return null
  }
}

// The value of one cookie in a raw Cookie header (for middleware that has no cookie jar). Null when absent.
export function readCookie(cookieHeader: string | null | undefined, name: string = GV_ID_COOKIE): string | null {
  if (!cookieHeader) return null
  for (const pair of cookieHeader.split(';')) {
    const i = pair.indexOf('=')
    if (i < 0) continue
    if (pair.slice(0, i).trim() === name) return pair.slice(i + 1).trim() || null
  }
  return null
}

// Where a site's "Sign in" sends someone: the one sign-in page, coming back to `returnTo` afterwards.
export function gvSignInUrl(returnTo: string): string {
  return `${GV_ID_SIGN_IN_URL}?to=${encodeURIComponent(returnTo)}`
}
