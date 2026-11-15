// The shared gv_id vectors. gv-identity.vectors.json is the same file every app carries, so each reader answers every
// case the same way.
import { describe, it, expect } from 'vitest'
import { verifyGvId, readCookie, gvSignInUrl, GV_ID_AUDIENCE } from '../src/index'
import vectors from './gv-identity.vectors.json'

describe('verifyGvId against the shared vectors', () => {
  for (const c of vectors.cases) {
    it(`${c.name} -> ${c.email ?? 'refused'}`, async () => {
      const got = await verifyGvId(c.token, { audience: GV_ID_AUDIENCE, publicKeyJwk: vectors.publicJwk, now: vectors.now })
      expect(got).toEqual(c.email ? { email: c.email } : null)
    })
  }
  it('refuses the valid vector under a different key', async () => {
    const valid = vectors.cases.find(c => c.name === 'valid')!
    const other = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify'])
    const jwk = await crypto.subtle.exportKey('jwk', other.publicKey)
    expect(await verifyGvId(valid.token, { audience: GV_ID_AUDIENCE, publicKeyJwk: jwk, now: vectors.now })).toBeNull()
  })
  it('refuses the valid vector for a different audience', async () => {
    const valid = vectors.cases.find(c => c.name === 'valid')!
    expect(await verifyGvId(valid.token, { audience: 'example.org', publicKeyJwk: vectors.publicJwk, now: vectors.now })).toBeNull()
    expect(await verifyGvId(valid.token, { audience: '', publicKeyJwk: vectors.publicJwk, now: vectors.now })).toBeNull()
  })
  it('refuses null, undefined and an oversized value without throwing', async () => {
    const o = { audience: GV_ID_AUDIENCE, publicKeyJwk: vectors.publicJwk }
    expect(await verifyGvId(null, o)).toBeNull()
    expect(await verifyGvId(undefined, o)).toBeNull()
    expect(await verifyGvId('a'.repeat(5000), o)).toBeNull()
  })
})

describe('regression: a missing or wrong option refuses (it already failed closed)', () => {
  const valid = vectors.cases.find(c => c.name === 'valid')!
  it('refuses no options, no audience, no key and an oct key', async () => {
    expect(await verifyGvId(valid.token, undefined as any)).toBeNull()
    expect(await verifyGvId(valid.token, { publicKeyJwk: vectors.publicJwk, now: vectors.now } as any)).toBeNull()
    expect(await verifyGvId(valid.token, { audience: GV_ID_AUDIENCE, now: vectors.now } as any)).toBeNull()
    expect(await verifyGvId(valid.token, { audience: GV_ID_AUDIENCE, now: vectors.now, publicKeyJwk: { kty: 'oct', k: 'AAAA' } })).toBeNull()
  })
})

describe('readCookie and gvSignInUrl', () => {
  it('reads gv_id out of a Cookie header', () => {
    expect(readCookie('a=1; gv_id=abc.def.ghi; b=2')).toBe('abc.def.ghi')
    expect(readCookie('a=1; xgv_id=nope')).toBeNull()
    expect(readCookie(null)).toBeNull()
  })
  it('sends a person to the one sign-in page with their return address', () => {
    expect(gvSignInUrl('https://faithwalk.garysheng.com/a?b=c')).toBe(
      'https://continent.garysheng.com/id/sign-in?to=https%3A%2F%2Ffaithwalk.garysheng.com%2Fa%3Fb%3Dc')
  })
})
