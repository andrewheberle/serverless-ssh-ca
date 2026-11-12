import { describe, it, expect } from "vitest"
import { serialParamSchema } from "../src/api/v4/schema.js"

describe("revoke certificate schema", () => {
	describe("serial", () => {
		const schema = serialParamSchema

		it("should fail with no params", async () => {
			const result = await schema.safeParseAsync(undefined)
			expect(result.success).toBe(false)
		})

		it("should pass with a string serial", async () => {
			const result = await schema.safeParseAsync({ serial: "12345678901234567890" })
			expect(result.success).toBe(true)
			expect(result.data?.serial).toBe(12345678901234567890n)
		})

		it("should pass with the maximum serial", async () => {
			const result = await schema.safeParseAsync({ serial: "18446744073709551615" })
			expect(result.success).toBe(true)
			expect(result.data?.serial).toBe(18446744073709551615n)
		})

		it("should fail with no serial", async () => {
			const result = await schema.safeParseAsync({ serial: undefined })
			expect(result.success).toBe(false)
		})

		it.each([
			["a number", 123],
			["an empty string", ""],
			["a leading zero", "01"],
			["a negative value", "-1"],
			["a decimal value", "1.5"],
			["a hex value", "0x10"],
			["surrounding whitespace", " 12 "],
			["a non-numeric value", "abc"],
			["a value larger than 64 bits", "18446744073709551616"],
		])("should fail with %s", async (_, serial) => {
			const result = await schema.safeParseAsync({ serial })
			expect(result.success).toBe(false)
		})
	})
})
