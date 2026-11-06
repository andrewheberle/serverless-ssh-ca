import { errors, type JWTPayload } from "jose"
import z from "zod"
import type { AdminAllowlist, AdminConfig } from "../config.js"
import { verifyJWTWithJWKS } from "../verify.js"

/** The settings of an admin UI that is turned on, see {@link AdminConfig} */
export type EnabledAdminConfig = Extract<AdminConfig, { kind: "enabled" }>

/**
 * Who is making a request to the admin UI, as established from the
 * identity-aware proxy's JWT, see ADR-0002.
 *
 * - `unauthenticated`: there is no JWT, or it is not valid, so the request gets 401
 * - `forbidden`: the JWT is valid but it is not for an admin, so the request gets 403. `email` is the JWT's email claim when it has one.
 * - `admin`: the request is from an admin, with their email exactly as the JWT gives it
 */
export type AdminAuthentication =
	| { kind: "unauthenticated", reason: string }
	| { kind: "forbidden", email: string | undefined, reason: string }
	| { kind: "admin", email: string }

// the email claim of the proxy's JWT, which must be set to something other
// than whitespace but is otherwise kept exactly as the JWT gives it
const EmailClaim = z.string().refine((v) => v.trim() !== "")

// the roles claim of the proxy's JWT, as one role or a list of them
const RolesClaim = z.union([z.string().transform((v) => [v]), z.array(z.string())])

/**
 * The roles in the proxy's JWT, which are none when the claim is missing or
 * is not a string or an array of strings.
 *
 * @param payload The verified payload of the proxy's JWT
 * @param claim The claim holding the roles
 * @param onWrongType Called when the claim is set but is neither a string nor an array of strings
 * @returns The roles
 */
export const rolesFromClaim = (payload: JWTPayload, claim: string, onWrongType: () => void): string[] => {
	const value = payload[claim]
	if (value === undefined) {
		return []
	}

	const roles = RolesClaim.safeParse(value)
	if (!roles.success) {
		onWrongType()
		return []
	}

	return roles.data
}

/**
 * Decides whether the email and roles in a verified proxy JWT are those of an
 * admin: their email, compared case-insensitively, is in the allowlist, or
 * one of their roles, compared exactly, is.
 *
 * @param payload The verified payload of the proxy's JWT
 * @param allowlist Who is an admin, see {@link AdminAllowlist}
 * @param onWrongRolesType Called when the roles claim is neither a string nor an array of strings
 * @returns Whether the JWT is for an admin, see {@link AdminAuthentication}
 */
export const authorizeAdmin = (payload: JWTPayload, allowlist: AdminAllowlist, onWrongRolesType: () => void): Exclude<AdminAuthentication, { kind: "unauthenticated" }> => {
	const email = EmailClaim.safeParse(payload.email)
	if (!email.success) {
		return { kind: "forbidden", email: undefined, reason: "the JWT has no email claim" }
	}

	if (allowlist.emails.includes(email.data.toLowerCase())) {
		return { kind: "admin", email: email.data }
	}

	const { roles } = allowlist
	if (roles !== undefined && rolesFromClaim(payload, roles.claim, onWrongRolesType).some((role) => roles.allowed.includes(role))) {
		return { kind: "admin", email: email.data }
	}

	return { kind: "forbidden", email: email.data, reason: "neither the email nor any role is allowed" }
}

/**
 * Authenticates a request to the admin UI from the JWT the identity-aware
 * proxy sends in the configured header, and decides whether it is from an
 * admin, see {@link authorizeAdmin}.
 *
 * @param jwt The value of the configured header, if the request has it
 * @param config The settings of the admin UI
 * @param onWrongRolesType Called when the roles claim is neither a string nor an array of strings
 * @returns Who is making the request, see {@link AdminAuthentication}
 */
export const authenticateAdmin = async (jwt: string | undefined, config: EnabledAdminConfig, onWrongRolesType: () => void): Promise<AdminAuthentication> => {
	if (jwt === undefined || jwt === "") {
		return { kind: "unauthenticated", reason: `the request has no ${config.header} header` }
	}

	let payload: JWTPayload
	try {
		payload = (await verifyJWTWithJWKS(jwt, config)).payload
	} catch (err) {
		// the reason is logged, so only the description of what failed is
		// kept, which never includes the JWT itself. Failing to fetch the
		// JWKS also refuses the request, so the UI fails closed
		const reason = err instanceof errors.JOSEError
			? `${err.code}: ${err.message}`
			: err instanceof Error ? `${err.name}: ${err.message}` : "the JWT could not be verified"
		return { kind: "unauthenticated", reason }
	}

	return authorizeAdmin(payload, config.allowlist, onWrongRolesType)
}
