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

type RemoteJWKSet = ReturnType<typeof createRemoteJWKSet>

// the remote JWKS for each URL, kept between requests so the keys that jose
// caches are reused rather than fetched again for every token
const remoteJWKSets = new Map<string, RemoteJWKSet>()

/**
 * Returns the remote JWKS for a URL, creating it on first use.
 *
 * jose caches the keys it fetches for up to 10 minutes and fetches them again
 * sooner when a token is signed with a key it does not have, so keys rotated
 * by the IdP are still picked up.
 *
 * @param url The URL of the JWKS
 * @returns The remote JWKS for the URL
 */
const remoteJWKSet = (url: string): RemoteJWKSet => {
	let jwks = remoteJWKSets.get(url)
	if (jwks === undefined) {
		jwks = createRemoteJWKSet(new URL(url))
		remoteJWKSets.set(url, jwks)
	}

	return jwks
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

	return await jwtVerify<CertificateRequestJWTPayload>(jwt, remoteJWKSet(env.JWT_JWKS_URL), {
		issuer: env.JWT_ISSUER,
		algorithms: split(env.JWT_ALGORITHMS),
		audience: audience,
	})
}
