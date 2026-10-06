import { env, exports } from "cloudflare:workers"
import {
	adminSecretsStore,
	// @ts-ignore: this import errors but is fine in tests
} from "cloudflare:test"
import { describe, it, expect } from "vitest"
import { privateKeyString } from "./keys/rsa"

// RSA CA keys are not supported, so every endpoint that uses the CA key
// should fail with a server error. chanfana hides the message of a 500 from
// clients, so the reason is only written to the logs
const admin = adminSecretsStore(env.PRIVATE_KEY)
await admin.create(privateKeyString)

describe("RSA CA key", () => {
	it.each([
		"/api/v3/ca",
		"/api/v3/user/krl",
		"/api/v3/host/krl",
	])("GET %s responds with a 500", async (path) => {
		const response = await exports.default.fetch(`http://example.com${path}`)

		expect(response.status).toBe(500)
		expect(await response.json()).toMatchObject({
			success: false,
			// chanfana InternalServerErrorException
			errors: [{ code: 7009 }],
		})
	})
})
