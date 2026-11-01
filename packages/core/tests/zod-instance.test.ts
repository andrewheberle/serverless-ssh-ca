import { createRequire } from "node:module"
import { describe, expect, it } from "vitest"

// chanfana adds .openapi() to the zod it loads itself, and the API schemas
// call .openapi() on the zod that core loads. When the install holds more
// than one copy of zod (for example when a dependency pins an exact zod that
// core's range doesn't accept), core gets a copy chanfana never extended and
// every module that builds a schema fails to load with ".openapi is not a
// function".
describe("zod", () => {
	it("should be the same copy for core and chanfana", () => {
		const fromCore = createRequire(import.meta.url)
		const fromChanfana = createRequire(fromCore.resolve("chanfana"))

		expect(
			fromCore.resolve("zod"),
			"core and chanfana load different copies of zod; run `npm ls zod` to see why",
		).toBe(fromChanfana.resolve("zod"))
	})
})
