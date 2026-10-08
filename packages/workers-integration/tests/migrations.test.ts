import { env, exports } from "cloudflare:workers"
// @ts-ignore: this import errors but is fine in tests
import { adminSecretsStore } from "cloudflare:test"
import { describe, it, expect } from "vitest"
import { privateKeyString } from "./keys/ecdsa"

const admin = adminSecretsStore(env.PRIVATE_KEY)
await admin.create(privateKeyString)

describe("database migrations", () => {
	it("are applied once when concurrent requests use a fresh database", async () => {
		const responses = await Promise.all(Array.from({ length: 10 }, () => exports.default.fetch("http://example.com/api/v3/user/krl")))

		expect(responses.map(r => r.status)).toEqual(Array.from({ length: 10 }, () => 200))

		const { results } = await env.DB.prepare("SELECT name FROM migrations").all()
		expect(results).toEqual([{ name: "0001_initial_schema" }])
	})
})
