import { createRemoteJWKSet, jwtVerify } from "jose"
import { CertificateRequestJWTPayload } from "./types"
import { env } from "cloudflare:workers"

export const verifyJWT = async (jwt: string) => {
    const JWKS = createRemoteJWKSet(new URL(env.JWT_JWKS_URL))

    return await jwtVerify<CertificateRequestJWTPayload>(jwt, JWKS, {
        issuer: env.JWT_ISSUER,
        algorithms: env.JWT_ALGORITHMS,
    })
}
