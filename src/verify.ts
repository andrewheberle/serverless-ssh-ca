import { createRemoteJWKSet, jwtVerify } from "jose"
import { CertificateRequestJWTPayload } from "./types"
import { env } from "cloudflare:workers"
import { split } from "./utils"

type VerifyOptions = {
	aud?: string | string[]
}

export const verifyJWT = async (jwt: string, opts: VerifyOptions = {}) => {
    const JWKS = createRemoteJWKSet(new URL(env.JWT_JWKS_URL))

	if (opts.aud !== undefined) {
		return await jwtVerify<CertificateRequestJWTPayload>(jwt, JWKS, {
			issuer: env.JWT_ISSUER,
			algorithms: split(env.JWT_ALGORITHMS),
			audience: opts.aud
		})
	}

    return await jwtVerify<CertificateRequestJWTPayload>(jwt, JWKS, {
        issuer: env.JWT_ISSUER,
        algorithms: split(env.JWT_ALGORITHMS),
    })
}
