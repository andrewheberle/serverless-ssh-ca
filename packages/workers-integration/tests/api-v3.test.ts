import { env } from "cloudflare:workers"
import {
	createExecutionContext,
	waitOnExecutionContext,
	// @ts-ignore: this import errors but is fine in tests
} from "cloudflare:test"
import { describe, it, expect } from "vitest"
import worker from "../src"

const IncomingRequest = Request<unknown, IncomingRequestCfProperties>

// written out rather than taken from the CA, as clients that still use API v3
// show this message to their users
const ApiV3RemovedMessage = "API v3 was removed in serverless-ssh-ca 1.0.0; upgrade ssh-ca-client to 0.24.0 or later"

const fetch = async (request: Request): Promise<Response> => {
	const ctx = createExecutionContext()
	const response = await worker.fetch(request, env, ctx)
	await waitOnExecutionContext(ctx)

	return response
}

describe("API v3", () => {
	it.each([
		{ method: "GET", path: "/api/v3/user/krl" },
		{ method: "POST", path: "/api/v3/user/certificate" },
	])("$method $path responds with a 410", async ({ method, path }) => {
		const response = await fetch(new IncomingRequest(`http://example.com${path}`, {
			method,
			headers: { "Content-Type": "application/json" },
			body: method === "GET" ? undefined : "{}",
		}))

		expect(response.status).toBe(410)
		expect(response.headers.get("content-type")).toContain("application/json")
		expect(await response.json()).toEqual({
			success: false,
			errors: [{ code: 410, message: ApiV3RemovedMessage }],
			result: {},
		})
	})
})
