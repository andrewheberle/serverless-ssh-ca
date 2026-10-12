import { createRemoteJWKSet, jwtVerify } from "jose"
import { CertificateRequestJWTPayload } from "./types.js"
import type { SshCaBindings } from "./types.js"
import { split } from "./utils.js"

/**
 * Thrown when no audience is configured for a token, as a token issued for
 * any client of the IdP would otherwise be accepted.
 */
export class MissingAudienceError extends Error {
	constructor(message: string) {
		super(message)
		this.name = "MissingAudienceError"

		Object.setPrototypeOf(this, MissingAudienceError.prototype)
	}
}

/**
 * Verifies a JWT from the IdP, including that it was issued for one of the
 * audiences given.
 *
 * @param env The CA bindings
 * @param jwt The JWT to verify
 * @param aud The audiences the JWT may be issued for, which must not be empty
 * @throws {@link MissingAudienceError} when no audience is given
 */
export const verifyJWT = async (env: SshCaBindings, jwt: string, aud: string | string[] | undefined) => {
	const audience = split(aud)
	if (audience.length === 0) {
		throw new MissingAudienceError("no audience is configured for verifying tokens, set JWT_AUD")
	}

	const JWKS = createRemoteJWKSet(new URL(env.JWT_JWKS_URL))

	return await jwtVerify<CertificateRequestJWTPayload>(jwt, JWKS, {
		issuer: env.JWT_ISSUER,
		algorithms: split(env.JWT_ALGORITHMS),
		audience: audience,
	})
}
