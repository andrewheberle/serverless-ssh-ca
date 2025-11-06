import { error, RequestHandler } from "itty-router"
import { createRemoteJWKSet, jwtVerify } from "jose"
import { JWSInvalid, JWTInvalid } from "jose/errors"
import { CFArgs } from "./router"
import { AuthenticatedRequest, CertificateRequestJWTPayload, LogLevel } from "./types"
import { env } from "cloudflare:workers"

export const withValidJWT: RequestHandler<AuthenticatedRequest, CFArgs> = async (request: AuthenticatedRequest, env: Env, ctx: ExecutionContext) => {
    try {
        // extract jwt from Authorization header
        const jwt = request.headers.get("Authorization")?.replace("Bearer ", "")
        if (jwt === undefined) {
            console.log({ level: LogLevel.Error, message: "request did not contain a JWT" })
            return error(401)
        }

        // verify jwt 
        const { payload } = await verifyJWT(jwt)

        if (payload.email === undefined) {
            console.log({ level: LogLevel.Error, message: "JWT was verified but was missing required email claim" })
            return error(400)
        }

        console.log({ level: LogLevel.Info, message: "validated JWT", for: payload.email })

        // add info to request
        request.sub = payload.sub
        request.email = payload.email
    } catch (err) {
        if (err instanceof JWSInvalid) {
            console.log({ level: LogLevel.Error, message: "the JWS was invalid", error: err })
            return error(400)
        } else if (err instanceof JWTInvalid) {
            console.log({ level: LogLevel.Error, message: "the JWT was invalid", error: err })
            return error(401)
        }

        // unhandled error, so log and throw it again and handle downstream
        console.log({ level: LogLevel.Error, message: "unhandled error", error: err })
        throw err
    }
}

export const verifyJWT = async function (jwt: string) {
    const JWKS = createRemoteJWKSet(new URL(env.JWT_JWKS_URL))
    return await jwtVerify<CertificateRequestJWTPayload>(jwt, JWKS, { issuer: env.JWT_ISSUER, algorithms: env.JWT_ALGORITHMS })
}
