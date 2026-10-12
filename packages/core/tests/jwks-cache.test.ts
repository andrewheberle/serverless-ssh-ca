import { describe, it, expect, vi, afterEach } from "vitest"
import { verifyJWT } from "../src/verify.js"
import { makeEnv } from "./env.js"
import { getIdentityToken } from "./helpers/token.js"

const port = parseInt(process.env.OIDC_PORT ?? "4567")
const audience = process.env.JWT_AUD ?? "audience"

// the number of requests made to a URL through the global fetch
const countRequests = (url: string): (() => number) => {
	const original = globalThis.fetch
	let count = 0
	vi.spyOn(globalThis, "fetch").mockImplementation(async (input, init) => {
		const target = input instanceof Request ? input.url : input.toString()
		if (target === url) {
			count++
		}
		return await original(input, init)
	})

	return () => count
}

describe("verifyJWT", () => {
	afterEach(() => {
		vi.restoreAllMocks()
	})

	it("should fetch the JWKS once for several tokens", async () => {
		// a URL no other test uses, so its keys are not already cached
		const url = `http://127.0.0.1:${port}/jwks`
		const requests = countRequests(url)
		const env = makeEnv({ JWT_JWKS_URL: url })

		for (const sub of ["user1", "user2", "user3"]) {
			const { payload } = await verifyJWT(env, await getIdentityToken({ sub, email: `${sub}@example.com` }), audience)
			expect(payload.sub).toBe(sub)
		}

		expect(requests()).toBe(1)
	})
})
