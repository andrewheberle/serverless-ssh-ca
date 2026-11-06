import { createRemoteJWKSet, jwtVerify, type JWTPayload, type JWTVerifyResult } from "jose"
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
 * Thrown when no issuer is configured for a token, as the issuer of a token is
 * otherwise not checked at all.
 */
export class MissingIssuerError extends Error {
	constructor(message: string) {
		super(message)
		this.name = "MissingIssuerError"

		Object.setPrototypeOf(this, MissingIssuerError.prototype)
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
 * What a JWT must be to be accepted by {@link verifyJWTWithJWKS}.
 */
export interface JWTRequirements {
	/** The URL of the JWKS the JWT must be signed with a key from */
	jwksUrl: string
	/** The issuer the JWT must have, which must not be empty */
	issuer: string
	/** The audiences the JWT may be issued for, which must not be empty */
	audience: string[]
	/** The algorithms the JWT may be signed with */
	algorithms: string[]
}

/**
 * Verifies a JWT against a remote JWKS, which is fetched once and cached
 * between requests, including that it was issued by the required issuer for
 * one of the required audiences. Both requester tokens and the JWTs of the
 * identity-aware proxy in front of the admin UI are verified this way.
 *
 * Callers must ensure the issuer and audience are not empty, as jose does not
 * check them otherwise; see {@link verifyJWT}, which does.
 *
 * @param jwt The JWT to verify
 * @param requirements What the JWT must be, see {@link JWTRequirements}
 * @returns The verified JWT
 */
export const verifyJWTWithJWKS = async <T extends JWTPayload>(jwt: string, requirements: JWTRequirements): Promise<JWTVerifyResult<T>> => {
	return await jwtVerify<T>(jwt, remoteJWKSet(requirements.jwksUrl), {
		issuer: requirements.issuer,
		algorithms: requirements.algorithms,
		audience: requirements.audience,
	})
}

/**
 * Verifies a JWT from the IdP, including that it was issued by the configured
 * issuer for one of the audiences given.
 *
 * @param config The bindings that say where the IdP's keys are and which tokens it issues
 * @param jwt The JWT to verify
 * @param aud The audiences the JWT may be issued for, which must not be empty
 * @throws {@link MissingAudienceError} when no audience is given
 * @throws {@link MissingIssuerError} when `JWT_ISSUER` is empty
 */
export const verifyJWT = async (config: Pick<SshCaBindings, "JWT_JWKS_URL" | "JWT_ISSUER" | "JWT_ALGORITHMS">, jwt: string, aud: string | string[] | undefined) => {
	const audience = split(aud)
	if (audience.length === 0) {
		throw new MissingAudienceError("no audience is configured for verifying tokens, set JWT_AUD")
	}

	// jose only checks the issuer when one is given, so an empty issuer would
	// accept tokens from any issuer the keys are trusted for
	if (typeof config.JWT_ISSUER !== "string" || config.JWT_ISSUER.trim() === "") {
		throw new MissingIssuerError("no issuer is configured for verifying tokens, set JWT_ISSUER")
	}

	return await verifyJWTWithJWKS<CertificateRequestJWTPayload>(jwt, {
		jwksUrl: config.JWT_JWKS_URL,
		issuer: config.JWT_ISSUER,
		algorithms: split(config.JWT_ALGORITHMS),
		audience: audience,
	})
}
