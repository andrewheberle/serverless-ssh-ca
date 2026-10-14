import type { Logger } from "@andrewheberle/ts-slog"
import { JWKInvalid, JWKSInvalid, JWSInvalid, JWSSignatureVerificationFailed, JWTClaimValidationFailed, JWTExpired, JWTInvalid } from "jose/errors"
import z from "zod"
import { CertificateType } from "./db/types.js"
import type { CertificateRequestJWTPayload, SshCaBindings } from "./types.js"
import { UserInfoClaimsError, userInfoIdentity, UserInfoRejectedError } from "./userinfo.js"
import { split } from "./utils.js"
import { MissingAudienceError, verifyJWT } from "./verify.js"

/**
 * The bindings used to authenticate a {@link Requester}.
 */
export type RequesterConfig = Pick<SshCaBindings,
	| "JWT_ALGORITHMS"
	| "JWT_AUD"
	| "JWT_ACCESS_TOKEN_AUD"
	| "JWT_ISSUER"
	| "JWT_JWKS_URL"
	| "JWT_SSH_CERTIFICATE_PRINCIPALS_CLAIM"
	| "OIDC_USERINFO_URL"
	| "SSH_HOST_CERTIFICATE_ALLOWED_EMAILS"
	| "SSH_HOST_CERTIFICATE_ALLOWED_ROLES"
>

/**
 * The person asking for a certificate, established from an access token and
 * an identity token for the same subject.
 */
export type Requester = {
	/** The email address from the access token */
	email: string
	/** The subject of both tokens */
	sub: string
	/** The principals from the identity token */
	principals: string[]
}

/**
 * The tokens a certificate request is authenticated with, as sent by the client.
 */
export type RequesterTokens = {
	/** The `Authorization` header, which carries the access token */
	authorization: string
	/** The identity token */
	identityToken: string
}

/**
 * Why a token was not accepted.
 */
export type TokenIssue = {
	token: "access" | "identity"
	message: string
}

/**
 * The result of {@link authenticate}.
 *
 * - `authenticated`: both tokens were accepted and the requester may request the certificate
 * - `invalid`: one or both tokens were not accepted
 * - `subjectMismatch`: the tokens were accepted but are for different subjects
 * - `notPermitted`: the requester may not request host certificates
 * - `misconfigured`: the CA is not configured to verify tokens
 * - `unavailable`: the IdP could not be asked whether the access token is valid
 */
export type AuthenticationResult =
	| { kind: "authenticated", requester: Requester }
	| { kind: "invalid", issues: TokenIssue[] }
	| { kind: "subjectMismatch", access: { email: string, sub: string }, identity: { sub: string } }
	| { kind: "notPermitted", requester: Requester }
	| { kind: "misconfigured", message: string }
	| { kind: "unavailable", message: string }

type TokenResult<T> =
	| { kind: "verified", value: T }
	| { kind: "invalid", message: string }
	| { kind: "misconfigured", message: string }
	| { kind: "unavailable", message: string }

type AccessToken = {
	email: string
	sub: string
}

type IdentityToken = {
	sub: string
	principals: string[]
}

/**
 * Thrown when a claim of a verified token is missing or is not of the
 * expected type.
 */
class TokenClaimError extends Error {
	constructor(message: string) {
		super(message)
		this.name = "TokenClaimError"

		Object.setPrototypeOf(this, TokenClaimError.prototype)
	}
}

const SubjectClaimSchema = z.string().min(1)

// returns the subject of a verified token, which is compared between the
// access and identity tokens so must always be present
const tokenSubject = (payload: { sub?: unknown }): string => {
	const parsed = SubjectClaimSchema.safeParse(payload.sub)
	if (!parsed.success) {
		throw new TokenClaimError("JWT was verified but was missing required sub claim")
	}

	return parsed.data
}

// the claims of an access token that identify the user's email address.
// email_verified is optional as not every IdP includes it, but when it is
// included it must be true, as an IdP may otherwise issue a token for an
// address the user has not shown they control.
const EmailClaimsSchema = z.object({
	email: z.email(),
	email_verified: z.boolean().optional(),
})

// returns the email address of a verified access token, or why it cannot be used
const tokenEmail = (payload: Record<string, unknown>): { ok: true, email: string } | { ok: false, error: string } => {
	if (payload.email === undefined) {
		return { ok: false, error: "JWT was verified but was missing required email claim" }
	}

	const parsed = EmailClaimsSchema.safeParse(payload)
	if (!parsed.success) {
		return { ok: false, error: "JWT was verified but the email or email_verified claim was not valid" }
	}

	if (parsed.data.email_verified === false) {
		return { ok: false, error: "JWT was verified but the email address has not been verified by the IdP" }
	}

	return { ok: true, email: parsed.data.email }
}

const PrincipalsClaimSchema = z.union([z.string(), z.array(z.string())]).nullish()

// returns the principals from a claim of a verified identity token, as the IdP
// sets the type of the claim
const identityPrincipals = (l: Logger, payload: CertificateRequestJWTPayload, claim: string): string[] => {
	const parsed = PrincipalsClaimSchema.safeParse(payload[claim])
	if (!parsed.success) {
		l.warn("claim was not a string or an array of strings", "claim", claim)
		throw new TokenClaimError(`the ${claim} claim must be a string or an array of strings`)
	}

	const p = parsed.data

	if (p === undefined) {
		l.warn("claim was missing despite being set in CA config", "claim", claim)
		return []
	}

	if (p === null) {
		l.warn("claim was present but was null", "claim", claim)
		return []
	}

	if (p === "") {
		l.warn("claim was present but was an empty string", "claim", claim)
		return []
	}

	// make sure its always a string[] and replace any spaces with underscores
	const principals = (typeof p === "string" ? [p] : p)
		.map((value) => value.replaceAll(" ", "_"))

	l.debug("identity token included principals", "principals", principals)

	return principals
}

// the attributes logged when a claim of a token is not valid, so the cause of a
// rejected token can be found without the token itself. The claims checked
// (such as aud, iss and nbf) identify the IdP and application, not the user.
const claimValidationAttributes = (err: JWTClaimValidationFailed): unknown[] => {
	return ["claim", err.claim, "reason", err.reason, "value", err.payload[err.claim]]
}

// verifies an access token with the IdP's userinfo endpoint, for IdPs that
// issue access tokens that are not JWTs
const verifyUserInfoAccessToken = async (l: Logger, url: string, token: string): Promise<TokenResult<AccessToken>> => {
	try {
		return { kind: "verified", value: await userInfoIdentity(url, token) }
	} catch (err) {
		switch (true) {
			case (err instanceof UserInfoRejectedError):
				l.warn(err.message, "status", err.status, "authenticate", err.authenticate)
				return { kind: "invalid", message: "the access token was not accepted by the userinfo endpoint" }
			case (err instanceof UserInfoClaimsError):
				l.warn(err.message)
				return { kind: "invalid", message: err.message }
			default:
				l.error("the access token could not be verified with the userinfo endpoint", "error", err)
				return { kind: "unavailable", message: "the access token could not be verified with the userinfo endpoint" }
		}
	}
}

const verifyAccessToken = async (config: RequesterConfig, logger: Logger, authorization: string): Promise<TokenResult<AccessToken>> => {
	const l = logger.with("in", "verifyAccessToken")

	if (!authorization.startsWith("Bearer ") || authorization.length <= 7) {
		return { kind: "invalid", message: "authorization header must be a Bearer token" }
	}

	const token = authorization.replace("Bearer ", "")

	// when a userinfo endpoint is configured every access token is verified
	// with it, rather than only those that are not JWTs, so a token cannot
	// avoid the checks of either method by its format
	if (config.OIDC_USERINFO_URL !== undefined && config.OIDC_USERINFO_URL !== "") {
		return await verifyUserInfoAccessToken(l, config.OIDC_USERINFO_URL, token)
	}

	try {
		// verify jwt, which must be issued for this CA
		const aud = split(config.JWT_ACCESS_TOKEN_AUD).length > 0 ? config.JWT_ACCESS_TOKEN_AUD : config.JWT_AUD
		const { payload } = await verifyJWT(config, token, aud)

		const email = tokenEmail(payload)
		if (!email.ok) {
			l.warn(email.error)
			return { kind: "invalid", message: email.error }
		}

		return { kind: "verified", value: { email: email.email, sub: tokenSubject(payload) } }
	} catch (err) {
		switch (true) {
			case (err instanceof MissingAudienceError):
				l.error(err.message)
				return { kind: "misconfigured", message: err.message }
			case (err instanceof TokenClaimError):
				return { kind: "invalid", message: err.message }
			case (err instanceof JWSInvalid):
				return { kind: "invalid", message: "the access token was invalid" }
			case (err instanceof JWTInvalid):
				return { kind: "invalid", message: "the access token failed verification" }
			case (err instanceof JWKInvalid):
				return { kind: "invalid", message: "the access token JWK was invalid" }
			case (err instanceof JWKSInvalid):
				return { kind: "invalid", message: "the access token JWKS was invalid" }
			case (err instanceof JWTClaimValidationFailed):
				l.warn("claim validation of the access token failed", ...claimValidationAttributes(err))
				return { kind: "invalid", message: "claim validation of the JWT failed" }
			case (err instanceof JWTExpired):
				return { kind: "invalid", message: "the access token has expired" }
			case (err instanceof JWSSignatureVerificationFailed):
				return { kind: "invalid", message: "the access token signature verification failed" }
			default:
				l.error("unhandled access token validation error", "error", err)
				return { kind: "invalid", message: "unhandled access token validation error" }
		}
	}
}

const verifyIdentityToken = async (config: RequesterConfig, logger: Logger, token: string): Promise<TokenResult<IdentityToken>> => {
	const l = logger.with("in", "verifyIdentityToken")

	try {
		const { payload } = await verifyJWT(config, token, config.JWT_AUD)

		return {
			kind: "verified",
			value: {
				sub: tokenSubject(payload),
				principals: identityPrincipals(l, payload, config.JWT_SSH_CERTIFICATE_PRINCIPALS_CLAIM),
			},
		}
	} catch (err) {
		if (err instanceof MissingAudienceError) {
			l.error(err.message)
			return { kind: "misconfigured", message: err.message }
		}
		if (err instanceof JWTClaimValidationFailed) {
			l.warn("claim validation of the identity token failed", ...claimValidationAttributes(err))
		}

		return { kind: "invalid", message: err instanceof TokenClaimError ? err.message : "problem parsing identity token" }
	}
}

// whether a requester may request host certificates, by their email address
// or a principal from their identity token
const mayRequestHostCertificates = (config: RequesterConfig, requester: Requester): boolean => {
	const roles = split(config.SSH_HOST_CERTIFICATE_ALLOWED_ROLES)

	return split(config.SSH_HOST_CERTIFICATE_ALLOWED_EMAILS).includes(requester.email)
		|| requester.principals.some((p) => roles.includes(p))
}

/**
 * Establishes who is asking for a certificate from the access token and
 * identity token of the request, and whether they may request a certificate
 * of the given type.
 *
 * The access token is verified with the IdP's userinfo endpoint when
 * `OIDC_USERINFO_URL` is set, or otherwise as a JWT issued for
 * `JWT_ACCESS_TOKEN_AUD` (or `JWT_AUD` when that is not set). The identity
 * token is always verified as a JWT issued for `JWT_AUD`. Both tokens are
 * verified, so a request with two tokens that are not accepted is told about
 * both, and they must be for the same subject, so a token issued to another
 * user cannot be substituted for either.
 *
 * @param config The bindings used to verify the tokens, see {@link RequesterConfig}
 * @param tokens The tokens sent with the request, see {@link RequesterTokens}
 * @param certificateType The type of certificate requested
 * @param logger The logger for the request
 * @returns The {@link Requester}, or why one could not be established, see {@link AuthenticationResult}
 */
export const authenticate = async (config: RequesterConfig, tokens: RequesterTokens, certificateType: CertificateType, logger: Logger): Promise<AuthenticationResult> => {
	const [access, identity] = await Promise.all([
		verifyAccessToken(config, logger, tokens.authorization),
		verifyIdentityToken(config, logger, tokens.identityToken),
	])

	// a CA that cannot verify tokens is reported before tokens that were not accepted
	for (const result of [access, identity]) {
		if (result.kind === "misconfigured" || result.kind === "unavailable") {
			return result
		}
	}

	if (access.kind !== "verified" || identity.kind !== "verified") {
		const issues: TokenIssue[] = []
		if (access.kind === "invalid") {
			issues.push({ token: "access", message: access.message })
		}
		if (identity.kind === "invalid") {
			issues.push({ token: "identity", message: identity.message })
		}

		return { kind: "invalid", issues }
	}

	if (access.value.sub !== identity.value.sub) {
		return { kind: "subjectMismatch", access: access.value, identity: { sub: identity.value.sub } }
	}

	const requester: Requester = {
		email: access.value.email,
		sub: access.value.sub,
		principals: identity.value.principals,
	}

	switch (certificateType) {
		case CertificateType.User:
			return { kind: "authenticated", requester }
		case CertificateType.Host:
			return mayRequestHostCertificates(config, requester)
				? { kind: "authenticated", requester }
				: { kind: "notPermitted", requester }
		default: {
			const unknownType: never = certificateType
			throw new Error(`unknown certificate type: ${String(unknownType)}`)
		}
	}
}
