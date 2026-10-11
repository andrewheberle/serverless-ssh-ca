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
		["/api/v4/ca", "get", "CA"],
		["/api/v4/user/certificates", "post", "User"],
		["/api/v4/user/certificates/{serial}", "delete", "User"],
		["/api/v4/user/krl", "get", "User"],
		["/api/v4/host/certificates", "post", "Host"],
		["/api/v4/host/certificates/{serial}/renew", "post", "Host"],
		["/api/v4/host/certificates/{serial}", "delete", "Host"],
		["/api/v4/host/krl", "get", "Host"],
	] as const)("should document %s %s tagged %s", (path, method, tag) => {
		expect(paths[path]?.[method]?.tags).toEqual([tag])
	})

	it("should use a unique operationId for every operation", () => {
		const operationIds = Object.values(paths).flatMap((operations) => Object.values(operations ?? {}).map((operation) => (operation as { operationId?: string }).operationId))

		expect(operationIds).not.toContain(undefined)
		expect(new Set(operationIds).size).toBe(operationIds.length)
	})

	it.each([
		"/api/v4/user/certificates",
		"/api/v4/host/certificates",
		"/api/v4/user/certificates/{serial}",
		"/api/v4/host/certificates/{serial}",
		"/api/v4/host/certificates/{serial}/renew",
	])("should document the proof of possession header for %s", (path) => {
		const operations = Object.values(paths[path] ?? {}) as { parameters?: { name: string, in: string, required?: boolean }[] }[]

		expect(operations).not.toHaveLength(0)
		for (const operation of operations) {
			expect(operation.parameters).toContainEqual(expect.objectContaining({ name: "Proof-Of-Possession", in: "header", required: true }))
		}
	})

	it("should not use a path parameter for the certificate type", () => {
		expect(Object.keys(paths).filter((p) => p.includes("{certificateType}"))).toEqual([])
	})
})
