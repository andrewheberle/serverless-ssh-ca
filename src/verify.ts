import { RequestHandler, StatusError } from "itty-router"
import { createRemoteJWKSet, jwtVerify } from "jose"
import { JWSInvalid, JWTInvalid } from "jose/errors"
import { CFArgs } from "./router"
import { AuthenticatedRequest, CertificateRequestJWTPayload, LogLevelError, LogLevelInfo } from "./types"
import { env } from "cloudflare:workers"

export const withValidJWT: RequestHandler<AuthenticatedRequest, CFArgs> = async (request: AuthenticatedRequest, env: Env, ctx: ExecutionContext) => {
    try {
        // extract jwt from Authorization header
        const jwt = request.headers.get("Authorization")?.replace("Bearer ", "")
        if (jwt === undefined) {
            console.log({ level: LogLevelError, message: "request did not contain a JWT" })
            throw new StatusError(401)
        }

        // verify jwt 
        const { payload } = await verifyJWT(jwt)

        if (payload.email === undefined) {
            console.log({ level: LogLevelError, message: "JWT was verified but was missing required email claim" })
            throw new StatusError(400)
        }

        console.log({ level: LogLevelInfo, message: "validated JWT", for: payload.email })

        // add info to request
        request.sub = payload.sub
        request.email = payload.email
    } catch (err) {
        if (err instanceof JWSInvalid) {
            console.log({ level: LogLevelError, message: "the JWS was invalid", error: err })
            throw new StatusError(400)
        } else if (err instanceof JWTInvalid) {
            console.log({ level: LogLevelError, message: "the JWT was invalid", error: err })
            throw new StatusError(401)
        } else if (err instanceof StatusError) {
            // any StatusError types should have their own logging
            throw err
        }

        // unhandled error, so just log and throw it again
        console.log({ level: LogLevelError, error: err })
        throw err
    }
}

export const verifyJWT = async function (jwt: string) {
    const JWKS = createRemoteJWKSet(new URL(env.JWT_JWKS_URL))
    return await jwtVerify<CertificateRequestJWTPayload>(jwt, JWKS, { issuer: env.JWT_ISSUER, algorithms: env.JWT_ALGORITHMS })
}
