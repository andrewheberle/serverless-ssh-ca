import { RequestHandler, StatusError } from "itty-router"
import { createRemoteJWKSet, jwtVerify } from "jose"
import { JWSInvalid, JWTInvalid } from "jose/errors"
import { CFArgs } from "./router"
import { AuthenticatedRequest, CertificateRequestJWTPayload } from "./types"
import { env } from "cloudflare:workers"

export const withValidJWT: RequestHandler<AuthenticatedRequest, CFArgs> = async (request: AuthenticatedRequest, env: Env, ctx: ExecutionContext) => {
    try {
        // extract jwt from Authorization header
        const jwt = request.headers.get("Authorization")?.replace("Bearer ", "")
        if (jwt === undefined) {
            throw new StatusError(401)
        }

        // verify jwt 
        const { payload } = await verifyJWT(jwt)

        if (payload.email === undefined) {
            console.error("JWT was verified but was missing email claim")
            throw new StatusError(400)
        }

        console.log(`Validated JWT for ${payload.email}`)

        // add info to request
        request.sub = payload.sub
        request.email = payload.email
    } catch (err) {
        if (err instanceof JWSInvalid) {
            throw new StatusError(400)
        } else if (err instanceof JWTInvalid) {
            throw new StatusError(401)
        } else if (err instanceof StatusError) {
            throw err
        }

        console.log(err)
        throw new StatusError(503)
    }
}

export const verifyJWT = async function (jwt: string) {
    const JWKS = createRemoteJWKSet(new URL(env.JWT_JWKS_URL))
    return await jwtVerify<CertificateRequestJWTPayload>(jwt, JWKS, { issuer: env.JWT_ISSUER, algorithms: env.JWT_ALGORITHMS })
}
