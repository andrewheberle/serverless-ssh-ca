import { error, IRequestStrict, RequestHandler } from "itty-router"
import { createRemoteJWKSet, jwtVerify } from "jose"
import { JWSInvalid, JWTInvalid } from "jose/errors"
import { CFArgs } from "./router"
import { CertificateRequestJWTPayload } from "./types"

export type AuthenticatedRequest = {
    email?: string
    principals?: string[]
} & IRequestStrict

export const verifyJWT: RequestHandler<AuthenticatedRequest, CFArgs> = async (request: AuthenticatedRequest, env: Env, ctx: ExecutionContext) => {
    try {
        // extract jwt from Authorization header
        const jwt = request.headers.get("Authorization")?.replace("Bearer ", "")
        if (jwt === undefined) {
            return error(401)
        }

        // verify jwt against JWKS
        const JWKS = createRemoteJWKSet(new URL(env.JWT_JWKS_URL))
        const { payload } = await jwtVerify<CertificateRequestJWTPayload>(jwt, JWKS, { audience: env.JWT_AUD, algorithms: env.JWT_ALGORITHMS })

        // add info to request
        request.email = payload.email
        request.principals = payload.principals
    } catch (err) {
        if (err instanceof JWSInvalid) {
            return error(400)
        } else if (err instanceof JWTInvalid) {
            return error(401)
        }

        console.log(err)
        return error(503)
    }
}