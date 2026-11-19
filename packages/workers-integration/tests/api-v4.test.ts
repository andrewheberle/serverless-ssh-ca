import { env } from "cloudflare:workers"
import {
    adminSecretsStore,
    createExecutionContext,
    waitOnExecutionContext,
    // @ts-ignore: this import errors but is fine in tests
} from "cloudflare:test"
import { describe, it, expect, beforeAll } from "vitest"
import { inject } from "vitest"
import worker from "../src"
import { privateKeyString, userKey } from "./keys/ecdsa"
import { getAccessToken, getIdentityToken } from "./helpers/token"

const IncomingRequest = Request<unknown, IncomingRequestCfProperties>

const admin = adminSecretsStore(env.PRIVATE_KEY)
await admin.create(privateKeyString)

const fetch = async (request: Request): Promise<Response> => {
    const ctx = createExecutionContext()
    const response = await worker.fetch(request, env, ctx)
    await waitOnExecutionContext(ctx)

    return response
}

describe("post /api/v4/user/certificates", () => {
    let accessToken: string
    let identityToken: string

    beforeAll(async () => {
        const claims = {
            sub: "user123",
            email: "user@example.com"
        }
        accessToken = await getAccessToken(claims)
        identityToken = await getIdentityToken(claims)
    })

    const issue = async (proof?: string): Promise<Response> => {
        const headers = new Headers()
        headers.set("Authorization", accessToken)
        headers.set("Content-Type", "application/json")
        if (proof !== undefined) {
            headers.set("Proof-Of-Possession", proof)
        }

        return await fetch(new IncomingRequest("http://example.com/api/v4/user/certificates", {
            method: "POST",
            headers,
            body: JSON.stringify({
                public_key: Buffer.from(userKey.publicKey).toString("base64"),
                identity: identityToken,
                lifetime: 3600,
            }),
        }))
    }

    it("valid request issues a certificate", async () => {
        const response = await issue(inject("testRequestProof"))

        expect(response.status).toBe(200)
        const result = await response.json<{ certificate: string }>()
        expect(() => atob(result.certificate)).not.toThrow()
    })

    it("request without a proof returns 400", async () => {
        expect((await issue()).status).toBe(400)
    })

    it("request with a proof that is not bound to the request returns 400", async () => {
        expect((await issue(inject("testRevokeRequestProof"))).status).toBe(400)
    })
})

describe("delete /api/v4/user/certificates/{serial}", () => {
    it("request with a proof that is not bound to the request returns 400", async () => {
        const headers = new Headers()
        headers.set("Proof-Of-Possession", inject("testRequestProof"))

        const response = await fetch(new IncomingRequest("http://example.com/api/v4/user/certificates/1234", { method: "DELETE", headers }))

        expect(response.status).toBe(400)
    })
})

describe("GET /api/v4/user/krl", () => {
    it("normal request", async () => {
        const response = await fetch(new IncomingRequest("http://example.com/api/v4/user/krl"))

        expect(response.status).toBe(200)
        expect(response.headers.get("content-type")).toContain("application/json")
    })

    it("should list revoked certificates until 24 hours after they expire", async () => {
        // apply the migrations, then record revoked user certificates that
        // expire in an hour, expired 23 hours ago and expired 25 hours ago
        expect((await fetch(new IncomingRequest("http://example.com/api/v4/user/krl"))).status).toBe(200)
        const hoursFromNow = (hours: number): string => new Date(Date.now() + hours * 3_600_000).toISOString()
        const record = env.DB.prepare("INSERT INTO certificates (serial, key_id, principals, valid_after, valid_before, revoked_at, certificate_type) VALUES (?, 'key', 'UID=alice', '2000-01-01T00:00:00.000Z', ?, '2000-01-01T00:00:00.000Z', 0)")
        await env.DB.batch([
            record.bind("717171", hoursFromNow(1)),
            record.bind("727272", hoursFromNow(-23)),
            record.bind("737373", hoursFromNow(-25)),
        ])

        const response = await fetch(new IncomingRequest("http://example.com/api/v4/user/krl"))
        expect(response.status).toBe(200)
        const body: unknown = await response.json()
        if (typeof body !== "object" || body === null || !("krl" in body) || typeof body.krl !== "string") {
            throw new Error("the response has no KRL")
        }
        const krl = Buffer.from(body.krl, "base64")

        // serials are listed in the KRL as 64-bit big-endian integers
        const listed = (serial: bigint): boolean => {
            const bytes = Buffer.alloc(8)
            bytes.writeBigUInt64BE(serial)
            return krl.includes(bytes)
        }
        expect(listed(717171n)).toBe(true)
        expect(listed(727272n)).toBe(true)
        expect(listed(737373n)).toBe(false)
    })
})
