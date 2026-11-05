import { afterEach, describe, it, expect, vi } from "vitest"
import { DatabaseSync } from "node:sqlite"
import ca, { cloudflareClientIp, createSshCa, InvalidConfigurationError, type CaRateLimiter, type SshCa, type SshCaOptions } from "../src/index.js"
import { fromNodeSqlite, secretFromString } from "../src/node/index.js"
import { makeEnv } from "./env.js"
import { generateProof, generateRequestProof } from "./helpers/proof.js"
import { key as ed25519Key } from "./keys/ed25519.js"
import { key as ecdsaKey } from "./keys/ecdsa.js"

const userKey = ecdsaKey.user()

// a rate limiter that records the keys it is asked about and allows or
// refuses every request
const fakeLimiter = (outcome: boolean | "throw"): CaRateLimiter & { keys: string[] } => {
	const keys: string[] = []
	return {
		keys,
		limit: async ({ key }) => {
			keys.push(key)
			if (outcome === "throw") {
				throw new Error("limiter unavailable")
			}
			return { success: outcome }
		},
	}
}

// createSshCa requires a rate limit key with a rate limiter, so the CA is
// keyed by the client IP address set by Cloudflare unless another is given
const createCa = (limiter: CaRateLimiter | undefined, options: SshCaOptions = { rateLimitKey: cloudflareClientIp }): SshCa => createSshCa(makeEnv({
	DB: fromNodeSqlite(new DatabaseSync(":memory:")),
	PRIVATE_KEY: secretFromString(ed25519Key.ca().privateKey),
	RATE_LIMITER: limiter,
}), options)

// revokes a serial that was never issued, which is not found unless the
// request is rate limited first
const revoke = async (ca: SshCa, headers: Record<string, string> = { "CF-Connecting-IP": "192.0.2.1" }): Promise<Response> => {
	return await ca.fetch(new Request("http://example.com/api/v4/user/certificates/12345", {
		method: "DELETE",
		headers: { "Proof-Of-Possession": generateRequestProof(userKey, "DELETE", "/api/v4/user/certificates/12345"), ...headers },
	}))
}

describe("rate limiting", () => {
	it("should not limit requests when there is no rate limiter", async () => {
		expect((await revoke(createCa(undefined))).status).toBe(404)
	})

	it("should allow requests the rate limiter allows, keyed by the client IP address", async () => {
		const limiter = fakeLimiter(true)
		expect((await revoke(createCa(limiter))).status).toBe(404)
		expect(limiter.keys).toEqual(["192.0.2.1"])
	})

	it("should respond with a 429 to requests the rate limiter refuses", async () => {
		const response = await revoke(createCa(fakeLimiter(false)))
		expect(response.status).toBe(429)
		expect(await response.json()).toMatchObject({ success: false, errors: [{ code: 7008, message: "Too Many Requests" }] })
	})

	it("should limit v3 requests", async () => {
		const limiter = fakeLimiter(false)
		const response = await createCa(limiter).fetch(new Request("http://example.com/api/v3/user/revoke", {
			method: "POST",
			headers: { "Content-Type": "application/json", "CF-Connecting-IP": "192.0.2.1" },
			body: JSON.stringify({ serial: "12345", public_key: Buffer.from(userKey.publicKey).toString("base64"), proof: generateProof(userKey) }),
		}))
		expect(response.status).toBe(429)
		expect(limiter.keys).toEqual(["192.0.2.1"])
	})

	it.each([
		"/api/v4/ca",
		"/api/v4/user/krl",
		"/api/v3/host/krl",
	])("should not limit GET %s", async (path) => {
		const limiter = fakeLimiter(false)
		const response = await createCa(limiter).fetch(new Request(`http://example.com${path}`, { headers: { "CF-Connecting-IP": "192.0.2.1" } }))
		expect(response.status).toBe(200)
		expect(limiter.keys).toEqual([])
	})

	it("should not limit requests without a key", async () => {
		const limiter = fakeLimiter(false)
		expect((await revoke(createCa(limiter), {})).status).toBe(404)
		expect(limiter.keys).toEqual([])
	})

	it("should use the rate limit key from the options", async () => {
		const limiter = fakeLimiter(true)
		const keyed = createCa(limiter, { rateLimitKey: (req) => req.headers.get("X-Real-IP") ?? undefined })
		expect((await revoke(keyed, { "X-Real-IP": "198.51.100.7", "CF-Connecting-IP": "192.0.2.1" })).status).toBe(404)
		expect(limiter.keys).toEqual(["198.51.100.7"])
	})

	it("should not limit requests when the rate limiter fails", async () => {
		expect((await revoke(createCa(fakeLimiter("throw")))).status).toBe(404)
	})
})

describe("the rate limit key", () => {
	afterEach(() => {
		vi.restoreAllMocks()
	})

	const env = (limiter: CaRateLimiter | undefined, overrides = {}) => makeEnv({
		DB: fromNodeSqlite(new DatabaseSync(":memory:")),
		PRIVATE_KEY: secretFromString(ed25519Key.ca().privateKey),
		RATE_LIMITER: limiter,
		...overrides,
	})

	it("should be required by createSshCa when there is a rate limiter", () => {
		expect(() => createSshCa(env(fakeLimiter(true)))).toThrow(InvalidConfigurationError)
		expect(() => createSshCa(env(fakeLimiter(true)))).toThrow("rateLimitKey")
	})

	it("should not be required by createSshCa without a rate limiter", () => {
		expect(() => createSshCa(env(undefined))).not.toThrow()
	})

	it("should be the client IP address set by Cloudflare for the Workers default export", async () => {
		const limiter = fakeLimiter(true)
		const ctx = { waitUntil: () => undefined, passThroughOnException: () => undefined, props: {} }

		const response = await ca.fetch(new Request("http://example.com/api/v4/user/certificates/12345", {
			method: "DELETE",
			headers: { "Proof-Of-Possession": generateRequestProof(userKey, "DELETE", "/api/v4/user/certificates/12345"), "CF-Connecting-IP": "192.0.2.1" },
		}), env(limiter), ctx)

		expect(response.status).toBe(404)
		expect(limiter.keys).toEqual(["192.0.2.1"])
	})

	it("should be reported once when requests have none, which are not limited", async () => {
		const log = vi.spyOn(console, "log").mockImplementation(() => undefined)
		const limiter = fakeLimiter(false)
		const keyless = createSshCa(env(limiter, { LOG_LEVEL: "warning" }), { rateLimitKey: () => undefined })

		expect((await revoke(keyless, {})).status).toBe(404)
		expect((await revoke(keyless, {})).status).toBe(404)

		expect(limiter.keys).toEqual([])
		const warnings = log.mock.calls.filter(([entry]) => (entry as { message?: string }).message === "requests without a rate limit key are not rate limited")
		expect(warnings).toHaveLength(1)
		expect(warnings[0]?.[0]).toMatchObject({ level: "warning" })
	})
})
