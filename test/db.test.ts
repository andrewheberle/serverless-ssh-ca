import { describe, it, expect } from "vitest"
import { runStatement, shouldRetry } from "../src/db"
import { env } from "cloudflare:workers"

describe("shouldRetry", () => {
    it("retryable error", () => {
        expect(shouldRetry("D1 DB reset because its code was updated.", 1)).toBe(true)
    })

    it("retryable error with too many retries", () => {
        expect(shouldRetry("D1 DB reset because its code was updated.", 6)).toBe(false)
    })

    it("non-retryable error", () => {
        expect(shouldRetry("Exceeded maximum DB size.", 1)).toBe(false)
    })

    it("non-retryable error with too many retries (should never occur)", () => {
        expect(shouldRetry("Exceeded maximum DB size.", 6)).toBe(false)
    })
})

describe("runStatement", async () => {
    it("should return 1", async () => {
        const stmt = env.DB.prepare("SELECT 1 AS result")
        const res = await runStatement(stmt)

        expect(res.success).toBe(true)
        expect(res.results.length).toBe(1)
        expect(res.results[0]).toStrictEqual({result: 1})
    })
})

