import { caConfig } from "./config.js"
import { logger } from "./logger.js"
import type { SshCaBindings } from "./types.js"

// whether a value is an object with every one of the named methods, as a
// binding provided by the runtime must be
const hasMethods = (value: unknown, ...methods: string[]): boolean =>
	typeof value === "object" && value !== null && methods.every((method) => typeof Reflect.get(value, method) === "function")

/**
 * Whether a value can be used as the `DB` binding, see {@link SshCaBindings.DB}.
 *
 * @param value The value of the binding
 * @returns true when it has the methods of a database binding
 */
export const isDatabaseBinding = (value: unknown): boolean => hasMethods(value, "prepare", "batch")

// whether a setting has a value, as an empty string or list is the same as
// leaving it unset
const isSet = (value: unknown): boolean =>
	value !== undefined && value !== "" && !(Array.isArray(value) && value.length === 0)

// the end of every warning, as each of these will be refused in a later major release
const refusedLater = "and will be refused in a future major release"

/**
 * Returns a warning for each problem with a valid configuration that the CA
 * accepts today but that makes part of it not work, or that it ignores:
 *
 * - a `DB` or `PRIVATE_KEY` binding that is missing or not the expected shape
 * - a `RATE_LIMITER` or `CACHE` binding that is set but not the expected shape
 * - an `ISSUER_DN` with control characters, which would break the CA public key's line
 * - only one of `ADMIN_ALLOWED_ROLES` and `ADMIN_JWT_ROLES_CLAIM` while the admin UI is on, so roles are ignored
 * - `JWT_ACCESS_TOKEN_AUD` with `OIDC_USERINFO_URL`, which does not use it
 *
 * The configuration must already be valid, see {@link caConfig}.
 *
 * @param env The bindings
 * @returns The warnings, none for a configuration without these problems
 */
export const bindingWarnings = (env: SshCaBindings): string[] => {
	const warnings: string[] = []

	if (!isDatabaseBinding(env.DB)) {
		warnings.push(`the DB binding is missing or is not a database, so certificates cannot be issued, ${refusedLater}`)
	}
	if (!hasMethods(env.PRIVATE_KEY, "get")) {
		warnings.push(`the PRIVATE_KEY binding is missing or is not a secret, so certificates cannot be issued, ${refusedLater}`)
	}
	if (env.RATE_LIMITER !== undefined && !hasMethods(env.RATE_LIMITER, "limit")) {
		warnings.push(`the RATE_LIMITER binding is not a rate limiter, so requests are not limited, ${refusedLater}`)
	}
	if (env.CACHE !== undefined && !hasMethods(env.CACHE, "get", "put")) {
		warnings.push(`the CACHE binding is not a cache, so KRLs are not cached, ${refusedLater}`)
	}

	const settings = caConfig(env)
	if (/\p{Cc}/u.test(settings.issuerDn)) {
		warnings.push(`ISSUER_DN contains control characters, which break the line the CA public key is served as, ${refusedLater}`)
	}
	// when the admin UI is off for want of a roles setting, that is already
	// warned about, so only roles that an enabled admin UI ignores are warned about here
	if (settings.admin.kind === "enabled" && isSet(env.ADMIN_ALLOWED_ROLES) !== isSet(env.ADMIN_JWT_ROLES_CLAIM)) {
		const [set, unset] = isSet(env.ADMIN_ALLOWED_ROLES) ? ["ADMIN_ALLOWED_ROLES", "ADMIN_JWT_ROLES_CLAIM"] : ["ADMIN_JWT_ROLES_CLAIM", "ADMIN_ALLOWED_ROLES"]
		warnings.push(`${set} is set without ${unset}, so admins are not recognised by role, ${refusedLater}`)
	}
	if (settings.accessTokenAudience.length > 0 && settings.userinfoUrl !== undefined) {
		warnings.push(`JWT_ACCESS_TOKEN_AUD is set with OIDC_USERINFO_URL, which does not check the access token's audience, so it is ignored, ${refusedLater}`)
	}

	return warnings
}

// the bindings whose warnings have been logged, so they are logged once
// rather than for every request
const warned = new WeakSet<SshCaBindings>()

/**
 * Logs each of the {@link bindingWarnings} of a valid configuration once, at
 * warning level. The CA still serves requests with it.
 *
 * @param env The bindings, whose configuration must be valid
 */
export const warnAboutBindings = (env: SshCaBindings): void => {
	if (warned.has(env)) {
		return
	}
	warned.add(env)

	const l = logger(env)
	for (const warning of bindingWarnings(env)) {
		l.warn(warning)
	}
}
