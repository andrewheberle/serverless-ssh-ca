import { createRemoteJWKSet, jwtVerify } from "jose"
import { CertificateRequestJWTPayload } from "./types"
import { env } from "cloudflare:workers"
import { split } from "./utils"

export const verifyJWT = async (jwt: string) => {
    const JWKS = createRemoteJWKSet(new URL(env.JWT_JWKS_URL))
    const aud = env.JWT_AUD === undefined || env.JWT_AUD as string === "" ? undefined : split(env.JWT_AUD as string)

    return await jwtVerify<CertificateRequestJWTPayload>(jwt, JWKS, {
        issuer: env.JWT_ISSUER,
        algorithms: split(env.JWT_ALGORITHMS),
        audience: aud
    })
}
