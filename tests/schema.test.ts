import { describe, it, expect } from "vitest"
import { createUserCertificateRequestEndpointSchema } from "../src/api/v3/schema"
import { makeEnv } from "./env"
import { ZodError } from "zod"

const env = makeEnv()

describe("user certificate schema", () => {
    const userCertificateEndpoint = createUserCertificateRequestEndpointSchema(env)

    describe("headers", () => {
        it("should fail with no headers", () => {
            const result = userCertificateEndpoint.request.headers.safeParse({})
            expect(result.success).toBe(false)
        })

        it("should fail with missing header", () => {
            const result = userCertificateEndpoint.request.headers.safeParse({
                Authorization: undefined
            })
            expect(result.success).toBe(false)
        })

        it("should fail with non-Bearer token header", () => {
            const result = userCertificateEndpoint.request.headers.safeParse({
                Authorization: "Basic foo"
            })
            expect(result.success).toBe(false)
        })

        it("should fail with empty Bearer token", () => {
            const result = userCertificateEndpoint.request.headers.safeParse({
                Authorization: "Bearer "
            })
            expect(result.success).toBe(false)
        })
    })
})
