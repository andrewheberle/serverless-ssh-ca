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
import { privateKeyString, userPrivateKey } from "./keys/ecdsa"
import { getAccessToken, getIdentityToken } from "./helpers/token"

const IncomingRequest = Request<unknown, IncomingRequestCfProperties>

const admin = adminSecretsStore(env.PRIVATE_KEY)
await admin.create(privateKeyString)

describe("post /api/v3/user/certificate", () => {
    const proof = inject("testProof")

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

    it("valid request issues a certificate", async () => {
        const key = userPrivateKey()

        const headers = new Headers()
        headers.set("Authorization", accessToken)
        headers.set("Content-Type", "application/json")

        const body = JSON.stringify({
            public_key: Buffer.from(key.toPublic().toString("ssh")).toString("base64"),
            proof: proof,
            identity: identityToken,
            extensions: [],
            lifetime: 3600,
        })

        const request = new IncomingRequest("http://example.com/api/v3/user/certificate", {
            method: "POST",
            headers,
            body,
        })

        const ctx = createExecutionContext()
        const response = await worker.fetch(request, env, ctx)
        await waitOnExecutionContext(ctx)

        expect(response.status).toBe(200)
        expect(response.headers.get("content-type")).toContain("application/json")

        const result = await response.json<{ certificate: string }>()
        expect(result.certificate).toBeDefined()
        expect(() => atob(result.certificate)).not.toThrow()
    })

    it("mismatched token subjects returns 403", async () => {
        const key = userPrivateKey()

        const differentIdentityToken = await getIdentityToken({
            sub: "different-user",
            email: "other@example.com"
        })

        const headers = new Headers()
        headers.set("Authorization", accessToken)
        headers.set("Content-Type", "application/json")

        const body = JSON.stringify({
            public_key: Buffer.from(key.toPublic().toString("ssh")).toString("base64"),
            proof: proof,
            identity: differentIdentityToken,
            extensions: [],
            lifetime: 3600,
        })

        const request = new IncomingRequest("http://example.com/api/v3/user/certificate", {
            method: "POST",
            headers,
            body,
        })

        const ctx = createExecutionContext()
        const response = await worker.fetch(request, env, ctx)
        await waitOnExecutionContext(ctx)

        expect(response.status).toBe(403)
    })
})
