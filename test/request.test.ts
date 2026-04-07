import { env, exports } from "cloudflare:workers"
import {
	adminSecretsStore,
	createExecutionContext,
	waitOnExecutionContext,
	// @ts-ignore: this import errors but is fine in tests
} from "cloudflare:test"
import { describe, it, expect } from "vitest"
import worker from "../src"
import { privateKeyString } from "./keys/ecdsa"

const IncomingRequest = Request<unknown, IncomingRequestCfProperties>

describe("get /404", () => {
	it("responds with a 404", async () => {
		const response = await exports.default.fetch("http://example.com/404")
		expect(response.status).toBe(404)
	})
})

describe("get /docs", () => {
	it("responds with a 200", async () => {
		const response = await exports.default.fetch("http://example.com/docs")
		expect(response.status).toBe(200)
	})
})
const admin = adminSecretsStore(env.PRIVATE_KEY);
await admin.create(privateKeyString)

describe("get /api/v3/ca", () => {
	it("responds with a 200 and correct content", async () => {
		const request = new IncomingRequest("http://example.com/api/v3/ca")

		// Create an empty context to pass to `worker.fetch()`
		const ctx = createExecutionContext()
		const response = await worker.fetch(request, env, ctx)

		// Wait for all `Promise`s passed to `ctx.waitUntil()` to settle before running test assertions
		await waitOnExecutionContext(ctx)

		const content = (await response.text()).trim()

		expect(response.status).toBe(200)
		expect(response.headers.get("content-type")).toContain("text/plain")

		expect(content).toBe("ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBOuHkGuyTakRj+XUdS/2IHrfeqy4/N8bFVtlSLstcqK0m5ri/iZkSm5B8IZdrZlgm0ggNeb6bdh0uRsBgESVZxI= CN=SSH CA,O=Internet Widgets Pty Ltd,C=US")
	})
})

describe("post /api/v3/user/certificate", () => {
	it("incomplete request", async () => {
		const headers = new Headers()
		headers.set("Authorization", "Bearer foo")
		headers.set("Content-Type", "application/json")

		const request = new IncomingRequest("http://example.com/api/v3/user/certificate", { method: "POST", headers: headers, body: "{}" })

		// Create an empty context to pass to `worker.fetch()`
		const ctx = createExecutionContext()
		const response = await worker.fetch(request, env, ctx)

		// Wait for all `Promise`s passed to `ctx.waitUntil()` to settle before running test assertions
		await waitOnExecutionContext(ctx)

		// expect validation error
		expect(response.status).toBe(400)
	})
})

describe("GET /api/v3/user/krl", () => {
	it("normal request", async () => {
		const request = new IncomingRequest("http://example.com/api/v3/user/krl")

		// Create an empty context to pass to `worker.fetch()`
		const ctx = createExecutionContext()
		const response = await worker.fetch(request, env, ctx)

		// Wait for all `Promise`s passed to `ctx.waitUntil()` to settle before running test assertions
		await waitOnExecutionContext(ctx)

		// expect 200 ok
		expect(response.status).toBe(200)
		expect(response.headers.get("content-type")).toContain("application/json")
	})
})

describe("post /api/v3/host/certificate", () => {
	it("incomplete request", async () => {
		const headers = new Headers()
		headers.set("Authorization", "Bearer foo")
		headers.set("Content-Type", "application/json")

		const request = new IncomingRequest("http://example.com/api/v3/host/certificate", { method: "POST", headers: headers, body: "{}" })

		// Create an empty context to pass to `worker.fetch()`
		const ctx = createExecutionContext()
		const response = await worker.fetch(request, env, ctx)

		// Wait for all `Promise`s passed to `ctx.waitUntil()` to settle before running test assertions
		await waitOnExecutionContext(ctx)

		// expect validation error
		expect(response.status).toBe(400)
	})
})

describe("post /api/v3/host/renew", () => {
	it("incomplete request", async () => {
		const headers = new Headers()
		headers.set("Authorization", "Bearer foo")
		headers.set("Content-Type", "application/json")

		const request = new IncomingRequest("http://example.com/api/v3/host/renew", { method: "POST", headers: headers, body: "{}" })

		// Create an empty context to pass to `worker.fetch()`
		const ctx = createExecutionContext()
		const response = await worker.fetch(request, env, ctx)

		// Wait for all `Promise`s passed to `ctx.waitUntil()` to settle before running test assertions
		await waitOnExecutionContext(ctx)

		// expect validation error
		expect(response.status).toBe(400)
	})
})

describe("GET /api/v3/host/krl", () => {
	it("normal request", async () => {
		const request = new IncomingRequest("http://example.com/api/v3/host/krl")

		// Create an empty context to pass to `worker.fetch()`
		const ctx = createExecutionContext()
		const response = await worker.fetch(request, env, ctx)

		// Wait for all `Promise`s passed to `ctx.waitUntil()` to settle before running test assertions
		await waitOnExecutionContext(ctx)

		// expect 200 ok
		expect(response.status).toBe(200)
		expect(response.headers.get("content-type")).toContain("application/json")
	})
})


