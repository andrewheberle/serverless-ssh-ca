import { describe, it, expect } from "vitest"
import { createAccessTokenSchema, createIdentityTokenSchema } from "../src/api/v3/schema"
import { makeEnv } from "./env"
import { getAccessToken, getIdentityToken } from "./helpers/token"

const env = makeEnv()

describe("access token schema", () => {
	const accessTokenSchema = createAccessTokenSchema(env)

	it("should fail when blank", async () => {
		const result = await accessTokenSchema.safeParseAsync("")
		expect(result.success).toBe(false)
	})

	it("should fail without correct prefix", async () => {
		const result = await accessTokenSchema.safeParseAsync("Basic foo")
		expect(result.success).toBe(false)
	})

	it("should fail with invalid token", async () => {
		const result = await accessTokenSchema.safeParseAsync("Bearer foo")
		expect(result.success).toBe(false)
	})

	it("should pass with valid token", async () => {
		const token = await getAccessToken({
			sub: "1234567890",
			email: "user123@example.com"
		})

		const result = await accessTokenSchema.safeParseAsync(token)

		expect(result.success).toBe(true)
	})
})

describe("identity token schema", () => {
	const identityTokenSchema = createIdentityTokenSchema(env)

	it("should fail when blank", async () => {
		const result = await identityTokenSchema.safeParseAsync("")
		expect(result.success).toBe(false)
	})

	it("should fail with invalid token", async () => {
		const result = await identityTokenSchema.safeParseAsync("foo")
		expect(result.success).toBe(false)
	})

	it("should pass with valid token", async () => {
		const token = await getIdentityToken({
			sub: "1234567890",
			email: "user123@example.com"
		})

		const result = await identityTokenSchema.safeParseAsync(token)

		expect(result.success).toBe(true)
	})
})
