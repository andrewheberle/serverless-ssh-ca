import { afterEach, describe, expect, it, vi } from "vitest"
import { logger } from "../src/logger.js"
import { KeyParseError } from "../src/ssh/keys.js"
import { makeEnv } from "./env.js"

afterEach(() => {
	vi.restoreAllMocks()
})

describe("logger", () => {
	it("should log an error with its message and cause", () => {
		const log = vi.spyOn(console, "log").mockImplementation(() => undefined)
		const err = new KeyParseError("private key could not be decoded", new SyntaxError("invalid base64"))

		logger(makeEnv({ LOG_LEVEL: "error" })).error("failed", "error", err, "count", 1)

		expect(log).toHaveBeenCalledWith({
			level: "error",
			message: "failed",
			error: {
				name: "KeyParseError",
				message: "private key could not be decoded",
				cause: { name: "SyntaxError", message: "invalid base64", stack: expect.any(String) },
				stack: expect.any(String),
			},
			count: 1,
		})
		// the logged line must keep the message when serialised, as it is
		// written as JSON
		expect(JSON.stringify(log.mock.calls[0]?.[0])).toContain("private key could not be decoded")
	})

	it("should log a cause that is not an error as it is", () => {
		const log = vi.spyOn(console, "log").mockImplementation(() => undefined)

		logger(makeEnv({ LOG_LEVEL: "error" })).error("failed", "error", new Error("outer", { cause: "a reason" }))

		expect(log.mock.calls[0]?.[0]).toMatchObject({ error: { message: "outer", cause: "a reason" } })
	})

	it("should stop at a chain of causes that loops", () => {
		const log = vi.spyOn(console, "log").mockImplementation(() => undefined)
		const err = new Error("loop")
		err.cause = err

		logger(makeEnv({ LOG_LEVEL: "error" })).error("failed", "error", err)

		expect(JSON.stringify(log.mock.calls[0]?.[0])).toContain("loop")
	})
})
