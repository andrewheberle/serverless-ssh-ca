# Security Review: serverless-ssh-ca

| | |
|---|---|
| Date | 2026-10-12 |
| Version reviewed | v0.23.0 (`95c586d`) |
| Scope | `packages/core` (API v3 and v4, OIDC token handling, proof of possession, certificate issuance and renewal, revocation and KRL, SSH and SSHSIG parsing, database layer, Node.js helpers), example Workers configuration, GitHub Actions workflows |
| Out of scope | `ssh-ca-client` (Go client), Cloudflare platform configuration, the IdP itself |
| Method | Manual code review, plus proof-of-concept tests run against the real request handlers (see [Appendix](#appendix-proof-of-concept-tests)) |

## Summary

The cryptographic core is in good shape. Proof-of-possession signatures,
certificate signature checks, KRL signing and SSH wire-format parsing are
careful and well tested. Most findings are about **authorization policy**:
who can get a certificate for which principals, and how a certificate can
be withdrawn once issued.

| # | Severity | Finding | Verified |
|---|---|---|---|
| 1 | **High** | Host certificate principals are not restricted, so wildcards and other hosts' names are accepted | PoC |
| 2 | **Medium/High** | The access token's audience is never checked, and the identity token's audience is optional | PoC |
| 3 | **Medium** | Renewal does not replace the old certificate, so revoking the renewed one can be undone by renewing again | PoC |
| 4 | **Medium** | Only the key holder can revoke a certificate; there is no administrator revocation | Code |
| 5 | **Medium** | `SSH_CERTIFICATE_INCLUDE_SELF` uses the email local-part as a principal, which can collide across domains, and `email_verified` is not checked | Code |
| 6 | Low | The subject-match check passes when neither token has a `sub` claim | PoC |
| 7 | Low | No rate limiting, and the JWKS is fetched again on every request | Code |
| 8 | Low | Configuration validation gaps (HTTP JWKS URL, negative retention, Workers vars not validated) | Code |
| 9 | Low | v3 proofs of possession can be replayed against other endpoints (already documented) | Code |
| 10 | Info | Smaller hardening and robustness items | Code |

---

## Findings

### 1. High: host certificate principals are not restricted

**Where:** `packages/core/src/api/v4/index.ts:167-176`, `packages/core/src/api/v3/index.ts:128-137`

Any user in `SSH_HOST_CERTIFICATE_ALLOWED_EMAILS` or `SSH_HOST_CERTIFICATE_ALLOWED_ROLES`
can ask for a host certificate with **any** list of principals. The only check
is `z.array(z.string()).min(1)`. The PoC got a 30-day host certificate with
the principal `*`:

```
"keyId":"host_*", "principals":["*"], "kind":"host"
```

OpenSSH (8.5 and later) treats host certificate principals as wildcard
patterns. A certificate for `*` is therefore accepted for every host covered
by a client's `@cert-authority` line. Even without wildcards, a requester can
name any other host, such as `db01.example.com`.

**Impact:** Anyone allowed to request host certificates, and anyone who
steals their IdP session, can impersonate any SSH server that trusts the CA.
They can then intercept credentials and sessions (MITM). Because renewal
needs no OIDC authentication (finding 3), the forged certificate can be
renewed indefinitely.

**Recommendations:**
- Reject principals that contain the wildcard characters `*`, `?` or `!`, as
  well as commas, whitespace and control characters.
- Add a server-side policy for host principals, for example
  `SSH_HOST_CERTIFICATE_ALLOWED_DOMAINS` (principals must be a hostname under
  an allowed suffix), and ideally a mapping from requester or role to the
  domains they may certify.
- Consider limiting how many principals one host certificate can have.

### 2. Medium/High: token audience is not enforced

**Where:** `packages/core/src/utils.ts:73` (access token, no `audience`),
`packages/core/src/utils.ts:213-214` and `packages/core/src/verify.ts` (identity
token audience only checked when `JWT_AUD` is set), `packages/core/src/node/env.ts:51`
(`JWT_AUD` optional)

- The `Authorization` access token is verified only for issuer, signature and
  expiry. Its `aud` is never checked. The PoC got a certificate with an access
  token for `aud: "some-other-app"`.
- `JWT_AUD` is optional. When it is unset, the identity token's audience is
  not checked either. The PoC got a certificate with **both** tokens issued
  for another audience.

Most real IdPs, Cloudflare Access included, issue tokens for many
applications from one issuer and JWKS. Without an audience check, any
relying party on the same IdP can obtain an SSH certificate as that user,
using a token it legitimately received. This includes a malicious or
compromised internal app, or any SaaS app using the same Access team domain.
The access token's `email` claim, which becomes the certificate key ID and
(optionally) a principal, comes from the unchecked token.

**Recommendations:**
- Make `JWT_AUD` required: fail start-up in `bindingsFromEnv`, and return a
  500 at request time on Workers if it is missing.
- Check the access token's audience too, against `JWT_AUD` or a separate
  `JWT_ACCESS_TOKEN_AUD`.
- Consider taking `email` from the audience-checked identity token rather than
  the access token.

### 3. Medium: renewal does not replace the old certificate

**Where:** `packages/core/src/api/v4/index.ts:186-228`, `packages/core/src/api/v3/index.ts:147-180`, `packages/core/src/utils.ts:374-404`

Renewal issues a new certificate (B) but leaves the old one (A) valid and
renewable until it expires. The PoC:

1. Issue host certificate A.
2. Renew A, which gives B.
3. Revoke B: `200`.
4. Renew A again: `200`, which gives a new valid certificate C.

Someone with the host private key can keep a chain going for as long as any
unexpired, unrevoked certificate exists. To stop them, the defender has to
find and revoke every outstanding serial. No endpoint lists them.

**Recommendations:**
- On renewal, revoke the presented certificate, or mark it superseded and
  refuse to renew it again.
- Optionally cap the total lifetime of a renewal chain (for example, require
  OIDC re-authentication every N renewals or N days).
- Consider adding public-key revocation (KRL `KRL_SECTION_EXPLICIT_KEY` or
  `KRL_SECTION_FINGERPRINT_SHA256`), so one action withdraws every certificate
  for a compromised key.

### 4. Medium: no administrator revocation

**Where:** `packages/core/src/api/operations.ts:173-211`, `packages/core/src/db/index.ts:118-140`

The only way to revoke is a proof of possession from the certificate's own
private key. An operator cannot revoke when:
- a laptop is lost or stolen (the key is with the thief),
- an employee leaves (the key is with them),
- a host key is compromised and the legitimate host has been rebuilt.

In each case the certificate stays valid until it expires: 24 hours for
users and **30 days for hosts** by default. Host certificates can also be
renewed indefinitely (finding 3).

**Recommendations:** Add an authenticated admin endpoint (OIDC role-gated)
to revoke by serial, by key ID or email, or by public key fingerprint. Add a
way to list the certificates issued to a subject or key. Until then,
document that lifetime is the only control over a lost key, and keep host
lifetimes short.

### 5. Medium: email identity handling

**Where:** `packages/core/src/certificate.ts:281-298`, `packages/core/src/utils.ts:75-82`

- With `SSH_CERTIFICATE_INCLUDE_SELF=true`, the principal is
  `email.split("@")[0]`. `alice@corp.com`, `alice@contractor.io` and
  `alice@gmail.com` all get the principal `alice`. This is exploitable when
  the IdP accepts more than one domain, for example Cloudflare Access with
  one-time PIN, GitHub or Google login, or B2B guests.
- `email_verified` is not checked. Some IdPs let users set an unverified
  email.
- `email` is not checked to be a string (`payload.email` is typed by cast
  only). This goes against the repository's own rule to validate data that
  crosses a trust boundary with Zod.

**Claim types.** `verifyJWT<CertificateRequestJWTPayload>` only tells the
TypeScript compiler what shape to assume. jose checks the signature and the
registered claims (`iss`, `aud`, `exp`, `nbf`), but nothing else. The only
runtime check on `email` is `!== undefined`, and `sub` is not checked at all.
Results with `SSH_CERTIFICATE_INCLUDE_SELF=true`:

| `email` claim | Result |
|---|---|
| `42`, `true`, `["a@x.com","b@x.com"]`, `{"a":1}` | `500 Internal Error` (fails while encoding the key ID or splitting the email) |
| `""` | `200`, key ID `""` |
| `"root"` (not an email address) | `200`, key ID `root`, **principal `root`** |

Wrong types fail closed, but as 500 errors that look like server faults. A
string that isn't an email address is accepted, and with `INCLUDE_SELF` the
whole string becomes a principal. Whether that can be exploited depends on
whether the IdP lets users set the claim. A missing or non-string `sub` leads
to finding 6.

**`email_verified`.** This is a standard OIDC claim (OpenID Connect Core
§5.1): a boolean that is `true` when the IdP has confirmed the user controls
the address. IdPs that allow self-registration or user-edited profiles (for
example Auth0 database connections, or Keycloak with self-registration) can
issue tokens with `email_verified: false` for an address the user doesn't
own. Not every IdP sends the claim. Microsoft Entra ID doesn't by default, and
Microsoft advises against using `email` for authorization. Check a real token
from your IdP (including Cloudflare Access) before deciding how strict to be.

**Recommendations:**
- Validate the verified payload with a Zod schema:
  `sub: z.string().min(1)`, `email: z.email()`, and
  `email_verified: z.boolean().optional()`. Return 401 or 403 on failure,
  not 500.
- Reject `email_verified === false`. Optionally add a setting that also
  requires it to be present and `true`, for IdPs that send it.
- Optionally add `SSH_CERTIFICATE_ALLOWED_EMAIL_DOMAINS`.
- Document that `INCLUDE_SELF` is only safe with a single-domain IdP.

### 6. Low: the subject-match check passes when `sub` is missing

**Where:** `packages/core/src/api/v4/index.ts:102`, `packages/core/src/api/v3/index.ts:65,123`

`data.body.identity.sub !== data.headers.Authorization.sub` is
`undefined !== undefined`, which is `false` when neither token has `sub`.
The PoC combined an access token for `victim@example.com` with an identity
token for `a@example.com`, neither with `sub`. It got a certificate with key
ID `victim@example.com` and the principals from the other token. Compliant
OIDC ID tokens always carry `sub`, so exploiting this needs an unusual IdP,
but the check should fail closed.

**Recommendation:** Require `sub` to be a non-empty string in both tokens
(this is covered by the Zod validation in finding 5).

### 7. Low: no rate limiting, and the JWKS is fetched on every request

**Where:** `packages/core/src/verify.ts:11`

- `createRemoteJWKSet` is called on every verification, so its built-in
  cache is thrown away. Each certificate request fetches the JWKS twice. That
  adds latency, can trip IdP rate limits (causing an outage), and makes the
  CA an amplifier towards the IdP.
- None of the endpoints is rate limited. Unauthenticated callers can
  repeatedly hit `/krl`, which reads the private key, queries the database,
  signs, and may write to the `krl` table. Authenticated users can mint
  unlimited certificates, which grows the database.

**Recommendations:** Create the JWKS once per `JWT_JWKS_URL` at module scope
and reuse it. Put Cloudflare rate-limiting rules or the Workers Rate Limiting
binding in front of the API (and document this for Node.js deployments).
Consider caching the KRL response briefly.

### 8. Low: configuration validation gaps

**Where:** `packages/core/src/node/env.ts`

- `JWT_JWKS_URL` accepts `http://`. A JWKS fetched over plain HTTP lets an
  on-path attacker substitute signing keys and forge any token. Require
  `https` (allow `http` only for `localhost` in tests).
- `DB_CERTIFICATE_RETENTION` accepts negative periods (`^[+-]?...`), for
  example `-30 days`. The cleanup job would then delete rows for certificates
  that are **still valid, including revoked ones**. Those serials would drop
  out of the KRL and out of the `isRevoked` check, so a revoked host
  certificate would become renewable again. Reject negative values.
- `EnvSchema` is only applied by `bindingsFromEnv` (Node.js). On Workers the
  vars are used unvalidated, so a typo (for example in a duration) only shows
  up as runtime errors. Validate `env` once in `createApp`.

### 9. Low: v3 proofs of possession can be replayed

**Where:** `packages/core/src/proof.ts:137-139`

This is already documented in `packages/core/README.md`. A v3 proof signs
only `${timestamp}.${fingerprint}`, so a captured proof can be replayed
against any other v3 endpoint for the same key within
`CERTIFICATE_REQUEST_TIME_SKEW_MAX` (90s by default). v4 fixes this.
**Recommendation:** Publish a deprecation date for `/api/v3`, and once the
client has moved to v4, add an option to turn v3 off.

### 10. Informational

- **Disallowed extensions return 500.** `CertificateError` from
  `generateCertificate` (`certificate.ts:309-315`) falls through to the
  default branch in `issueCertificate`. The same happens for a user with no
  principals. These should be 4xx responses.
- **No minimum RSA key size.** `ssh-rsa` subject keys of any size are
  certified. OpenSSH refuses keys under 1024 bits, but the CA should enforce
  a policy (at least 2048, or consider dropping RSA subject keys).
- **Unchecked IdP group names become principals.** The principals claim
  (`groups` by default) is copied straight into user certificates (spaces
  become `_`). If users can create or name groups in the IdP, they can choose
  principals such as `root`. Consider an allow-list or required prefix for
  principals taken from the claim.
- **Unreachable security-key code.** `sk-*` signature verification exists
  (`sshsig/verifier.ts`), but `PublicKey` rejects `sk-*` keys, so FIDO keys
  can't be used. If they are enabled later, check the user-presence flag.
- **Revocation race.** `revokeCertificate` updates by `serial` without
  `AND revoked_at IS NULL`. Concurrent revocations can overwrite
  `revoked_at`. This is harmless but easy to tighten.
- **Public API docs.** OpenAPI/Swagger docs are served without
  authentication at `/docs`. That is fine for this API, but worth knowing.

## Positive observations

- Proofs of possession check the claimed fingerprint, the key embedded in the
  signature, and the subject key, with separate SSHSIG namespaces for v3, v4
  and KRL signatures.
- v4 binds proofs to the method and path, with a canonical decimal serial so
  each request has exactly one form.
- Renewal checks the CA signature (including the CA key equality check),
  that the certificate is a host certificate, its validity and its revocation
  status. User certificates cannot be renewed without OIDC.
- Certificates with no principals are refused (OpenSSH would treat them as
  valid for anyone). Extensions are allow-listed. Lifetimes are capped by
  configuration.
- Serials are 64-bit CSPRNG values. A certificate is not returned unless it
  was recorded in the database, so every issued certificate can be revoked.
- Revocation reports "not found" for another key's serial, which prevents
  serial enumeration.
- All SQL is parameterised. Migrations are atomic and safe to run
  concurrently.
- The SSH and SSHSIG parsers reject trailing bytes, mismatched key types and
  bad ECDSA components. Verification failures return `false` and do not throw.
- The CA key must be an unencrypted Ed25519 or ECDSA key; RSA CA keys are
  rejected.
- CI hardening is good: actions are pinned by SHA, `permissions: {}` is the
  default, `persist-credentials: false` is set, and npm trusted publishing
  with attestations is used.

## Suggested priority

1. Restrict host principals (finding 1) and require and check the audience on both tokens (finding 2).
2. Supersede certificates on renewal and add administrator or by-key revocation (findings 3 and 4).
3. Validate token claims with Zod (findings 5 and 6).
4. Cache the JWKS, add rate limiting and tighten configuration validation (findings 7 and 8).

## Maintainer decisions

| # | Decision | Planned change |
|---|---|---|
| 1 | Accepted risk, partly fixed. Hosts are reached by IP address, bare hostname or FQDN, so the CA won't restrict which names it issues for. Wildcard names will be refused. | Reject host principals containing `*`, `?` or `!` (also worth refusing `,`, whitespace and control characters). |
| 2 | Fix. The audience becomes required. | Make `JWT_AUD` required (Node.js start-up and Workers request time), and check it on the access token as well as the identity token. |
| 3 | Fix. Renewing a host certificate revokes the certificate presented. | Revoke the presented certificate as part of renewal, so the KRL lists it and it can't be renewed again. |
| 4 | Deferred. An admin UI is on the roadmap. | None for now. Keep host lifetimes short in the meantime. |
| 5 | Needs review. | See the claim type and `email_verified` notes under finding 5. |
| 6 | Fix. A missing `sub` is a failure, not a skipped check. | Reject the request when either token lacks a non-empty string `sub` (part of the Zod claim validation in finding 5). |

## Appendix: proof-of-concept tests

These tests were run against `createSshCa` with the existing test helpers.
Save the file as `packages/core/tests/security-poc.test.ts` and run
`npx vitest run tests/security-poc.test.ts` (this needs `ssh-keygen` on
`PATH`). Results observed:

```
WILDCARD   status 200, kind host, principals ["*"], keyId "host_*"
ACCESS_AUD 200   (access token aud = "some-other-app")
NO_AUD     200   (JWT_AUD unset, both tokens aud = "some-other-app")
NO_SUB     200   (keyId "victim@example.com", tokens for different users, no sub)
RENEW_AFTER_REVOKE 200 200   (revoke B succeeds, then renewing A succeeds)
```

```ts
import { describe, it, beforeAll } from "vitest"
import { DatabaseSync } from "node:sqlite"
import { createSshCa, type SshCa } from "../src/index.js"
import { fromNodeSqlite, secretFromString } from "../src/node/index.js"
import { makeEnv } from "./env.js"
import { getAccessToken, getIdentityToken } from "./helpers/token.js"
import { generateRequestProof } from "./helpers/proof.js"
import { key as ed25519Key } from "./keys/ed25519.js"
import { key as ecdsaKey } from "./keys/ecdsa.js"
import { listCertificate } from "./helpers/ssh-keygen.js"

const email = "user@example.com"
const claims = { sub: "user123", email }
const pk = (k: { publicKey: string }) => Buffer.from(k.publicKey).toString("base64")
const req = (ca: SshCa, method: string, path: string, body: unknown, proof?: string, auth?: string) => {
	const h = new Headers({ "Content-Type": "application/json" })
	if (proof) h.set("Proof-Of-Possession", proof)
	if (auth) h.set("Authorization", auth)
	return ca.fetch(new Request(`http://x${path}`, { method, headers: h, body: body === undefined ? undefined : JSON.stringify(body) }))
}

describe("security PoC", () => {
	let ca: SshCa, caNoAud: SshCa
	const userKey = ecdsaKey.user(), hostKey = ecdsaKey.host()
	beforeAll(() => {
		ca = createSshCa(makeEnv({ DB: fromNodeSqlite(new DatabaseSync(":memory:")), PRIVATE_KEY: secretFromString(ed25519Key.ca().privateKey), SSH_HOST_CERTIFICATE_ALLOWED_EMAILS: email }))
		caNoAud = createSshCa(makeEnv({ JWT_AUD: undefined, DB: fromNodeSqlite(new DatabaseSync(":memory:")), PRIVATE_KEY: secretFromString(ed25519Key.ca().privateKey) }))
	})

	it("1: wildcard host principal", async () => {
		const r = await req(ca, "POST", "/api/v4/host/certificates",
			{ public_key: pk(hostKey), identity: await getIdentityToken(claims), principals: ["*"] },
			generateRequestProof(hostKey, "POST", "/api/v4/host/certificates"), await getAccessToken(claims))
		console.log(r.status, listCertificate(Buffer.from((await r.json()).certificate, "base64").toString()).principals)
	})

	it("2a: access token for another audience", async () => {
		const r = await req(ca, "POST", "/api/v4/user/certificates",
			{ public_key: pk(userKey), identity: await getIdentityToken(claims) },
			generateRequestProof(userKey, "POST", "/api/v4/user/certificates"), await getAccessToken({ ...claims, aud: "some-other-app" }))
		console.log(r.status)
	})

	it("2b: JWT_AUD unset, both tokens for another audience", async () => {
		const c = { ...claims, aud: "some-other-app", groups: ["ssh-admin"] }
		const r = await req(caNoAud, "POST", "/api/v4/user/certificates",
			{ public_key: pk(userKey), identity: await getIdentityToken(c) },
			generateRequestProof(userKey, "POST", "/api/v4/user/certificates"), await getAccessToken(c))
		console.log(r.status)
	})

	it("6: neither token has sub", async () => {
		const r = await req(ca, "POST", "/api/v4/user/certificates",
			{ public_key: pk(userKey), identity: await getIdentityToken({ email: "a@example.com" } as never) },
			generateRequestProof(userKey, "POST", "/api/v4/user/certificates"), await getAccessToken({ email: "victim@example.com" } as never))
		console.log(r.status)
	})

	it("3: renew superseded certificate after revoking the renewal", async () => {
		const a = await req(ca, "POST", "/api/v4/host/certificates",
			{ public_key: pk(hostKey), identity: await getIdentityToken(claims), principals: ["h1"] },
			generateRequestProof(hostKey, "POST", "/api/v4/host/certificates"), await getAccessToken(claims))
		const aCert = (await a.json()).certificate as string
		const aSerial = listCertificate(Buffer.from(aCert, "base64").toString()).serial
		const renew = (c: string, s: bigint) => req(ca, "POST", `/api/v4/host/certificates/${s}/renew`, { certificate: c },
			generateRequestProof(hostKey, "POST", `/api/v4/host/certificates/${s}/renew`))
		const bCert = (await (await renew(aCert, aSerial)).json()).certificate as string
		const bSerial = listCertificate(Buffer.from(bCert, "base64").toString()).serial
		const revoked = await req(ca, "DELETE", `/api/v4/host/certificates/${bSerial}`, undefined,
			generateRequestProof(hostKey, "DELETE", `/api/v4/host/certificates/${bSerial}`))
		console.log(revoked.status, (await renew(aCert, aSerial)).status)
	})
})
```
