import z from "zod"

// how long the userinfo endpoint is given to respond
const UserInfoTimeout = 10_000

/**
 * Thrown by {@link userInfoIdentity} when the userinfo endpoint does not
 * accept the access token, as the token is invalid, expired or revoked.
 */
export class UserInfoRejectedError extends Error {
	/** The HTTP status of the response */
	readonly status: number
	/** The `WWW-Authenticate` header of the response, which says why the token was not accepted */
	readonly authenticate: string | null

	constructor(status: number, authenticate: string | null) {
		super(`the userinfo endpoint did not accept the access token (status ${status})`)
		this.name = "UserInfoRejectedError"
		this.status = status
		this.authenticate = authenticate

		Object.setPrototypeOf(this, UserInfoRejectedError.prototype)
	}
}

/**
 * Thrown by {@link userInfoIdentity} when the claims returned by the userinfo
 * endpoint cannot be used to issue a certificate.
 */
export class UserInfoClaimsError extends Error {
	constructor(message: string) {
		super(message)
		this.name = "UserInfoClaimsError"

		Object.setPrototypeOf(this, UserInfoClaimsError.prototype)
	}
}

/**
 * Thrown by {@link userInfoIdentity} when the userinfo endpoint could not be
 * reached or did not respond as an OIDC userinfo endpoint should.
 */
export class UserInfoUnavailableError extends Error {
	constructor(message: string, cause?: unknown) {
		super(message, { cause })
		this.name = "UserInfoUnavailableError"

		Object.setPrototypeOf(this, UserInfoUnavailableError.prototype)
	}
}

// a userinfo response is a JSON object of claims (OpenID Connect Core 1.0, section 5.3.2)
const UserInfoResponseSchema = z.record(z.string(), z.unknown())

// the claims of a userinfo response that a certificate is issued for. As for
// an access token, email_verified is optional but must be true when included.
const UserInfoClaimsSchema = z.object({
	sub: z.string().min(1),
	email: z.email(),
	email_verified: z.boolean().optional(),
})

/**
 * Returns the subject and email address of the user an access token was
 * issued to, as returned by the IdP's OIDC userinfo endpoint.
 *
 * This allows access tokens that are not JWTs (opaque tokens) to be used, as
 * the IdP is asked whether the token is valid instead of its signature being
 * checked. The userinfo endpoint does not say which client a token was issued
 * to, so the subject must be checked against an identity token that was
 * verified to be issued for this CA.
 *
 * @param url The URL of the IdP's userinfo endpoint
 * @param token The access token, without the `Bearer ` prefix
 * @returns The `sub` and `email` claims of the user
 * @throws {@link UserInfoRejectedError} when the endpoint does not accept the token
 * @throws {@link UserInfoClaimsError} when the claims returned cannot be used
 * @throws {@link UserInfoUnavailableError} when the endpoint cannot be reached or its response is not valid
 */
export const userInfoIdentity = async (url: string, token: string): Promise<{ sub: string, email: string }> => {
	let response: Response
	try {
		response = await fetch(url, {
			headers: {
				"Authorization": `Bearer ${token}`,
				"Accept": "application/json",
			},
			signal: AbortSignal.timeout(UserInfoTimeout),
		})
	} catch (err) {
		throw new UserInfoUnavailableError("the userinfo endpoint could not be reached", err)
	}

	if (response.status === 401 || response.status === 403) {
		throw new UserInfoRejectedError(response.status, response.headers.get("WWW-Authenticate"))
	}

	if (!response.ok) {
		throw new UserInfoUnavailableError(`the userinfo endpoint responded with status ${response.status}`)
	}

	let body: unknown
	try {
		body = await response.json()
	} catch (err) {
		throw new UserInfoUnavailableError("the userinfo endpoint did not respond with JSON", err)
	}

	const claims = UserInfoResponseSchema.safeParse(body)
	if (!claims.success) {
		throw new UserInfoUnavailableError("the userinfo endpoint did not respond with a JSON object")
	}

	if (claims.data.email === undefined) {
		throw new UserInfoClaimsError("the userinfo response was missing required email claim")
	}

	const parsed = UserInfoClaimsSchema.safeParse(claims.data)
	if (!parsed.success) {
		throw new UserInfoClaimsError("the sub, email or email_verified claim of the userinfo response was not valid")
	}

	if (parsed.data.email_verified === false) {
		throw new UserInfoClaimsError("the email address in the userinfo response has not been verified by the IdP")
	}

	return { sub: parsed.data.sub, email: parsed.data.email }
}
