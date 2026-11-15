# @supersuit/gv-identity

The one verifier for the `gv_id` cookie: the single sign-in shared by every garysheng.com site.

## What the cookie is

A compact JWS signed with ES256 (P-256). The payload carries `{ email, iat, exp, aud }`; other claims are ignored. One issuer holds the private key. Every site that reads the cookie holds the public key.

## What it never grants

Identity only. The cookie says who someone is. It never says what they may open. Each site applies its own rule to the email this package returns.

## How a site reads it

```ts
import { verifyGvId, readCookie, GV_ID_AUDIENCE } from '@supersuit/gv-identity'

const token = readCookie(request.headers.get('cookie'))
const who = await verifyGvId(token, {
  audience: GV_ID_AUDIENCE,          // the audience this site accepts
  publicKeyJwk: ISSUER_PUBLIC_JWK,   // the issuer's public key, passed in by the site
})
if (who) {
  // who.email is verified and lowercase. Decide access here.
}
```

`verifyGvId` returns `{ email }` or `null`. It never throws. It refuses a wrong key, a wrong audience, an expired token, a token issued more than 60 seconds in the future, any algorithm but ES256, and any payload whose email is not already trimmed and lowercase. Pass `now` (milliseconds) in tests.

The package keeps no key. The public key is not a secret, but each site passes it in, so this package is never a trust anchor.

It uses Web Crypto only, with no `node:` imports. It runs in Next.js server routes, middleware, Edge and Node 20+.

Also exported: `readCookie`, `gvSignInUrl`, `GV_ID_COOKIE`, `GV_ID_AUDIENCE`, `GV_ID_SIGN_IN_URL`, `GV_ID_SIGN_OUT_URL`.

## The vectors file

`test/gv-identity.vectors.json` holds 18 cases signed once with a throwaway key (its public half is in the file). It is shipped in the package and is the same file every app carries. A reader that answers every case as the file says behaves like every other reader. Run it with `npm test`. An app imports the same file from the package:

```ts
import vectors from '@supersuit/gv-identity/vectors.json' with { type: 'json' }
```

Then run each case through `verifyGvId` with `vectors.publicJwk` and `vectors.now`, and expect `case.email` (or `null`).

## License

MIT
