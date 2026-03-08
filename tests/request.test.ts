import { SELF, env, createExecutionContext, waitOnExecutionContext } from "cloudflare:test"
import { describe, it, expect } from "vitest"
import worker from "../src"

const IncomingRequest = Request<unknown, IncomingRequestCfProperties>

describe("get /404", () => {
    it ("responds with a 404", async () => {
        const response = await SELF.fetch("http://example.com/404")
        expect(response.status).toBe(404)
    })
})

describe("get /docs", () => {
    it ("responds with a 200", async () => {
        const response = await SELF.fetch("http://example.com/docs")
        expect(response.status).toBe(200)
    })
})

describe("get /api/v2/ca", () => {
    it ("responds with a 200", async () => {
		const request = new IncomingRequest("http://example.com/api/v2/ca")
		
		// Create an empty context to pass to `worker.fetch()`
		const ctx = createExecutionContext()
		const response = await worker.fetch(request, env, ctx)
		
		// Wait for all `Promise`s passed to `ctx.waitUntil()` to settle before running test assertions
		await waitOnExecutionContext(ctx)
		
        expect(response.status).toBe(200)
    })
})
