import { describe, it, expect } from "vitest"
import { revokeCertificateEndpointBodySchema } from "../src/api/v3/schema.js"
import { createApp } from "../src/router.js"
import { makeEnv } from "./env.js"
import { key as ecdsaKey } from "./keys/ecdsa.js"
import { generateProof } from "./helpers/proof.js"

const env = makeEnv()

describe("revoke certificate schema", () => {
	describe("body", () => {
		const schema = revokeCertificateEndpointBodySchema(env)
		const key = ecdsaKey.user()
		const publicKey = Buffer.from(key.toPublic().toString("ssh")).toString("base64")
		const proof = generateProof(key)

		it("should fail with no body", async () => {
			const result = await schema.safeParseAsync(undefined)
			expect(result.success).toBe(false)
		})

		it("should pass with a string serial", async () => {
			const result = await schema.safeParseAsync({
				serial: "12345678901234567890",
				public_key: publicKey,
				proof: proof
			})
			expect(result.success).toBe(true)
			expect(result.data?.serial).toBe(12345678901234567890n)
		})

		it("should pass with the maximum serial", async () => {
			const result = await schema.safeParseAsync({
				serial: "18446744073709551615",
				public_key: publicKey,
				proof: proof
			})
			expect(result.success).toBe(true)
			expect(result.data?.serial).toBe(18446744073709551615n)
		})

		it("should fail with no serial", async () => {
			const result = await schema.safeParseAsync({
				serial: undefined,
				public_key: publicKey,
				proof: proof
			})
			expect(result.success).toBe(false)
		})

		it.each([
			["a number", 123],
			["an empty string", ""],
			["a negative value", "-1"],
			["a decimal value", "1.5"],
			["a hex value", "0x10"],
			["surrounding whitespace", " 12 "],
			["a non-numeric value", "abc"],
			["a value larger than 64 bits", "18446744073709551616"],
		])("should fail with %s", async (_, serial) => {
			const result = await schema.safeParseAsync({
				serial: serial,
				public_key: publicKey,
				proof: proof
			})
			expect(result.success).toBe(false)
		})
	})

	describe("openapi", () => {
		it("should publish serial as a string of digits", () => {
			const openapi = createApp(env).schema
			expect(openapi.components?.schemas?.["Certificate Revocation"]).toMatchObject({
				properties: {
					serial: {
						type: "string",
						pattern: "^\\d+$",
					}
				}
			})
		})
	})
})
