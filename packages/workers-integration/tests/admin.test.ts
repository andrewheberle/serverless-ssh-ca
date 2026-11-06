import { env } from "cloudflare:workers"
import {
    adminSecretsStore,
    createExecutionContext,
    waitOnExecutionContext,
    // @ts-ignore: this import errors but is fine in tests
} from "cloudflare:test"
import { describe, it, expect, beforeAll, beforeEach, afterEach, vi } from "vitest"
import { exportJWK, generateKeyPair, SignJWT, type CryptoKey, type JWK } from "jose"
import worker from "../src"
import { privateKeyString } from "./keys/ecdsa"

const admin = adminSecretsStore(env.PRIVATE_KEY)
await admin.create(privateKeyString)

// the identity-aware proxy in front of the admin UI. Its JWKS URL must be
// https, so it is served by stubbing fetch, which the worker shares with the
// tests as it runs in the same isolate
const issuer = "https://workers-test.cloudflareaccess.com"
const jwksUrl = `${issuer}/cdn-cgi/access/certs`
const audience = "workers-test-aud"
const origin = "https://ssh-ca.example.com"
const adminEmail = "Admin@Example.com"

let privateKey: CryptoKey
let jwks: { keys: JWK[] }

beforeAll(async () => {
    const pair = await generateKeyPair("RS256")
    privateKey = pair.privateKey
    jwks = { keys: [{ ...(await exportJWK(pair.publicKey)), kid: "proxy", alg: "RS256" }] }
})

beforeEach(() => {
    const original = globalThis.fetch
    vi.spyOn(globalThis, "fetch").mockImplementation(async (input, init) => {
        const url = input instanceof Request ? input.url : input.toString()
        return url === jwksUrl ? Response.json(jwks) : await original(input, init)
    })
})

afterEach(() => {
    vi.restoreAllMocks()
})

// the bindings with the admin UI turned on
const adminEnv = {
    ...env,
    ADMIN_JWT_HEADER: "Cf-Access-Jwt-Assertion",
    ADMIN_JWKS_URL: jwksUrl,
    ADMIN_JWT_ISSUER: issuer,
    ADMIN_JWT_AUD: audience,
    ADMIN_ALLOWED_EMAILS: "admin@example.com",
}

const fetch = async (request: Request): Promise<Response> => {
    const ctx = createExecutionContext()
    const response = await worker.fetch(request, adminEnv, ctx)
    await waitOnExecutionContext(ctx)

    return response
}

const jwt = async (): Promise<string> => await new SignJWT({ email: adminEmail })
    .setProtectedHeader({ alg: "RS256", kid: "proxy" })
    .setIssuer(issuer)
    .setAudience(audience)
    .setIssuedAt()
    .setExpirationTime("5m")
    .sign(privateKey)

describe("admin revocation on workerd", () => {
    it("should revoke a certificate and record who revoked it and why", async () => {
        // apply the migrations, then record a user certificate to revoke
        expect((await fetch(new Request(`${origin}/api/v4/user/krl`))).status).toBe(200)
        const serial = "424242"
        const now = Date.now()
        await env.DB.prepare("INSERT INTO certificates (serial, key_id, principals, extensions, valid_after, valid_before, certificate_type, public_key, requested_by) VALUES (?, ?, ?, ?, ?, ?, 0, ?, ?)")
            .bind(serial, "alice@example.com", "UID=alice", "permit-pty", new Date(now - 60_000).toISOString(), new Date(now + 3_600_000).toISOString(), null, "alice@example.com")
            .run()

        const response = await fetch(new Request(`${origin}/admin/user/certificates/${serial}/revoke`, {
            method: "POST",
            headers: {
                "Cf-Access-Jwt-Assertion": await jwt(),
                "Origin": origin,
                "Sec-Fetch-Site": "same-origin",
                "Content-Type": "application/x-www-form-urlencoded",
            },
            body: "reason=++Laptop+stolen+&confirm=yes",
        }))

        expect(response.status).toBe(303)
        expect(response.headers.get("Location")).toBe(`/admin/user/certificates/${serial}`)

        const recorded = await env.DB.prepare("SELECT revoked_at, revoked_by, revocation_reason FROM certificates WHERE serial = ?").bind(serial).first()
        expect(recorded).toMatchObject({ revoked_by: adminEmail, revocation_reason: "Laptop stolen" })
        expect(recorded?.revoked_at).not.toBeNull()

        const revision = await env.DB.prepare("SELECT revision FROM krl WHERE certificate_type = 0").first()
        expect(revision).toEqual({ revision: 1 })

        const detail = await fetch(new Request(`${origin}/admin/user/certificates/${serial}`, { headers: { "Cf-Access-Jwt-Assertion": await jwt() } }))
        expect(detail.status).toBe(200)
        expect(await detail.text()).toContain("<dt>Revocation reason</dt><dd>Laptop stolen</dd>")
    })

    it("should refuse a cross-site revocation", async () => {
        const response = await fetch(new Request(`${origin}/admin/user/certificates/1/revoke`, {
            method: "POST",
            headers: {
                "Cf-Access-Jwt-Assertion": await jwt(),
                "Origin": "https://evil.example.com",
                "Sec-Fetch-Site": "cross-site",
                "Content-Type": "application/x-www-form-urlencoded",
            },
            body: "reason=lost&confirm=yes",
        }))

        expect(response.status).toBe(403)
    })
})
