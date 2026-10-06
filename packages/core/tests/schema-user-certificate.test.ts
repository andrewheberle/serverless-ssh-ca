import { describe, it, expect } from "vitest"
import { createHeaderSchema, createIdentityTokenSchema, userCertificateRequestEndpointBodySchema } from "../src/api/v3/schema"
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

		it("should fail with an expired token", async () => {
			const token = await getAccessToken({
				sub: "1234567890",
				email: "user123@example.com",
				exp: Math.floor(Date.now() / 1000) - 3600,
			})

			const result = await schema.safeParseAsync({
				Authorization: token
			})

			expect(result.success).toBe(false)
			expect(result.error?.issues[0]?.message).toBe("the access token has expired")
		})

		it("should fail with a bad signature", async () => {
			const token = await getAccessToken({
				sub: "1234567890",
				email: "user123@example.com"
			})
			const other = await getAccessToken({
				sub: "0987654321",
				email: "other@example.com"
			})

			// keep the signature but replace the payload with another token's
			const [header, , signature] = token.split(".")
			const [, payload] = other.split(".")
			const result = await schema.safeParseAsync({
				Authorization: `${header}.${payload}.${signature}`
			})

			expect(result.success).toBe(false)
			expect(result.error?.issues[0]?.message).toBe("the access token signature verification failed")
		})

		it("should fail with the wrong issuer", async () => {
			const token = await getAccessToken({
				sub: "1234567890",
				email: "user123@example.com",
				iss: "https://idp.example.com",
			})

			const result = await schema.safeParseAsync({
				Authorization: token
			})

			expect(result.success).toBe(false)
			expect(result.error?.issues[0]?.message).toBe("claim validation of the JWT failed")
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

	describe("identity token principals claim", () => {
		const schema = createIdentityTokenSchema(env)

		it("should pass with a null claim and no principals", async () => {
			const token = await getIdentityToken({
				sub: "1234567890",
				email: "user123@example.com",
				groups: null,
			})

			const result = await schema.safeParseAsync(token)

			expect(result.success).toBe(true)
			expect(result.data?.principals).toEqual([])
		})

		it("should fail with a clear message for a claim of the wrong type", async () => {
			const token = await getIdentityToken({
				sub: "1234567890",
				email: "user123@example.com",
				groups: 42,
			})

			const result = await schema.safeParseAsync(token)

			expect(result.success).toBe(false)
			expect(result.error?.issues[0]?.message).toBe("the groups claim must be a string or an array of strings")
		})
	})
})
