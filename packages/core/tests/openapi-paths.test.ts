import { describe, it, expect } from "vitest"
import { createApp } from "../src/router.js"
import { makeEnv } from "./env.js"

const paths = createApp(makeEnv()).schema.paths ?? {}

describe("OpenAPI schema", () => {
	it.each([
		["/api/v3/ca", "get", "CA"],
		["/api/v3/user/certificate", "post", "User"],
		["/api/v3/user/krl", "get", "User"],
		["/api/v3/user/revoke", "post", "User"],
		["/api/v3/host/certificate", "post", "Host"],
		["/api/v3/host/renew", "post", "Host"],
		["/api/v3/host/krl", "get", "Host"],
		["/api/v3/host/revoke", "post", "Host"],
	] as const)("should document %s %s tagged %s", (path, method, tag) => {
		expect(paths[path]?.[method]?.tags).toEqual([tag])
	})

	it("should not use a path parameter for the certificate type", () => {
		expect(Object.keys(paths).filter((p) => p.includes("{certificateType}"))).toEqual([])
	})
})
