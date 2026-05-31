import { describe, it, expect } from "vitest"
import { createUserCertificateRequestEndpointSchema } from "../src/api/v3/schema"
import { makeEnv } from "./env"
import { ZodError } from "zod"

const env = makeEnv()

describe("user certificate schema", () => {
	const userCertificateEndpoint = createUserCertificateRequestEndpointSchema(env)

	it("should fail with no headers", () => {
		const result = userCertificateEndpoint.request.headers.safeParse({})
		expect(result.success).toBe(false)
	})
})
