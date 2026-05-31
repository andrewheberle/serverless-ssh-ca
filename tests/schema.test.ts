import { describe, it, expect } from "vitest"

import { createUserCertificateRequestEndpointSchema } from "../src/api/v3/schema"
import { makeEnv } from "./env"

const env = makeEnv()

describe("user certificate schema", () => {
	const userCertificateEndpoint = createUserCertificateRequestEndpointSchema(env)
	it("should fail no headers", () => {
		const result = userCertificateEndpoint.request.headers.parse({})
		expect(result).toBe("ok")
	})
})
