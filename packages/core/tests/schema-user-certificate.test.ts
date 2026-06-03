import { describe, it, expect } from "vitest"
import { createHeaderSchema, userCertificateRequestEndpointBodySchema } from "../src/api/v3/schema"
import { makeEnv } from "./env"
import { getAccessToken, getIdentityToken } from "./helpers/token"
import { key as ecdsaKey } from "./keys/ecdsa"
import { generateProof } from "./helpers/proof"
import { seconds } from "itty-time"

const env = makeEnv()

describe("user certificate schema", () => {
	const schema = createHeaderSchema(env)

	describe("headers", () => {
		it("should fail with no headers", async () => {
			const result = await schema.safeParseAsync({})
			expect(result.success).toBe(false)
		})

		it("should fail with missing header", async () => {
			const result = await schema.safeParseAsync({
				Authorization: undefined
			})
			expect(result.success).toBe(false)
		})

		it("should fail with without correct prefix", async () => {
			const result = await schema.safeParseAsync({
				Authorization: "Basic foo"
			})
			expect(result.success).toBe(false)
		})

		it("should fail with empty value after prefix", async () => {
			const result = await schema.safeParseAsync({
				Authorization: "Bearer "
			})
			expect(result.success).toBe(false)
		})

		it("should pass with valid token", async () => {
			const token = await getAccessToken({
				sub: "1234567890",
				email: "user123@example.com"
			})

			const result = await schema.safeParseAsync({
				Authorization: token
			})

			expect(result.success).toBe(true)
		})
	})

	describe("body", async () => {
		const schema = userCertificateRequestEndpointBodySchema(env)

		it("should fail with no body", async () => {
			const result = await schema.safeParseAsync(undefined)
			expect(result.success).toBe(false)
		})

		it("should fail with invalid body", async () => {
			const result = await schema.safeParseAsync({
				public_key: undefined,
				proof: undefined,
				identity: undefined
			})
			expect(result.success).toBe(false)
		})

		const token = await getIdentityToken({
			sub: "1234567890",
			email: "user123@example.com"
		})
		const key = ecdsaKey.user()
		const publicKey = Buffer.from(key.toPublic().toString("ssh")).toString("base64")
		const proof = generateProof(key)

		it("should fail with no proof", async () => {

			const result = await schema.safeParseAsync({
				public_key: publicKey,
				proof: undefined,
				identity: token
			})
			expect(result.success).toBe(false)
		})

		it("should fail with no identity", async () => {
			const result = await schema.safeParseAsync({
				public_key: publicKey,
				proof: proof,
				identity: undefined
			})
			expect(result.success).toBe(false)
		})

		it("should fail with no public_key", async () => {
			const result = await schema.safeParseAsync({
				public_key: undefined,
				proof: proof,
				identity: token
			})
			expect(result.success).toBe(false)
		})

		console.log({ publicKey, proof, token })

		it("should pass with valid body", async () => {
			const result = await schema.safeParseAsync({
				public_key: publicKey,
				proof: proof,
				identity: token
			})
			expect(result.success).toBe(true)
		})

		it("should pass with optional fields", async () => {
			const result = await schema.safeParseAsync({
				public_key: publicKey,
				proof: proof,
				identity: token,
				extensions: ["extension1", "extension2"],
				lifetime: 3600
			})
			expect(result.success).toBe(true)
		})

		it("should fail with lifetime too small", async () => {
			const result = await schema.safeParseAsync({
				public_key: publicKey,
				proof: proof,
				identity: token,
				extensions: ["extension1", "extension2"],
				lifetime: seconds("5 minutes") - 1
			})
			expect(result.success).toBe(false)
		})

		it("should fail with lifetime too big", async () => {
			const result = await schema.safeParseAsync({
				public_key: publicKey,
				proof: proof,
				identity: token,
				extensions: ["extension1", "extension2"],
				lifetime: seconds(env.SSH_CERTIFICATE_LIFETIME) + 1
			})
			expect(result.success).toBe(false)
		})

		it("should fail with invalid extensions", async () => {
			const result = await schema.safeParseAsync({
				public_key: publicKey,
				proof: proof,
				identity: token,
				extensions: null,
				lifetime: 3600
			})
			expect(result.success).toBe(false)
		})
	})
})
