import { env } from "cloudflare:workers"
import {
    adminSecretsStore,
    createExecutionContext,
    waitOnExecutionContext,
    // @ts-ignore: this import errors but is fine in tests
} from "cloudflare:test"
import { describe, it, expect } from "vitest"
import worker from "../src"
import { privateKeyString } from "./keys/ecdsa"

const admin = adminSecretsStore(env.PRIVATE_KEY)
await admin.create(privateKeyString)

const origin = "https://ssh-ca.example.com"

// the bindings with the landing page turned on
const landingEnv = {
    ...env,
    LANDING_PAGE: "true",
}

const fetch = async (request: Request, bindings: Env = landingEnv): Promise<Response> => {
    const ctx = createExecutionContext()
    const response = await worker.fetch(request, bindings, ctx)
    await waitOnExecutionContext(ctx)

    return response
}

describe("landing page on workerd", () => {
    it("should show the CA public key served by the API", async () => {
        const publicKey = (await (await fetch(new Request(`${origin}/api/v4/ca`))).text()).trim()

        const response = await fetch(new Request(`${origin}/`))

        expect(response.status).toBe(200)
        expect(response.headers.get("Content-Type")).toMatch(/^text\/html/)
        expect(response.headers.get("Content-Security-Policy")).toContain("default-src 'none'")
        const body = await response.text()
        expect(body).toContain(publicKey)
        expect(body).toContain(`curl -fsS ${origin}/api/v4/ca`)
    })

    it("should serve the stylesheet it links, at its hashed name, for anyone to cache", async () => {
        const body = await (await fetch(new Request(`${origin}/`))).text()
        const path = body.match(/<link rel="stylesheet" href="(\/style-[0-9a-f]{8}\.css)"\/>/)?.[1]
        expect(path).toBeDefined()

        const response = await fetch(new Request(`${origin}${path}`))

        expect(response.status).toBe(200)
        expect(response.headers.get("Content-Type")).toBe("text/css; charset=utf-8")
        expect(response.headers.get("Cache-Control")).toBe("public, max-age=31536000, immutable")
        expect((await fetch(new Request(`${origin}/style.css`))).status).toBe(404)
    })

    it("should answer with 404 while it is turned off", async () => {
        expect((await fetch(new Request(`${origin}/`), env)).status).toBe(404)
    })
})
