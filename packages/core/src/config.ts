import { ms } from "itty-time"
import z from "zod"
import { principalIssue } from "./principals.js"
import type { SshCaBindings } from "./types.js"

/**
 * Thrown when the CA's configuration is not valid, by `createSshCa` and by
 * `bindingsFromEnv` from `@andrewheberle/serverless-ssh-ca/node`.
 */
export class InvalidConfigurationError extends Error {
	constructor(message: string) {
		super(message)
		this.name = "InvalidConfigurationError"

		Object.setPrototypeOf(this, InvalidConfigurationError.prototype)
	}
}

/** A string that must be set to something other than whitespace */
export const RequiredString = z.string().trim().min(1, { message: "must be set" })

// a duration with a unit itty-time recognises. itty-time reads a unit it does
// not recognise, such as "secs", as milliseconds and a value it cannot parse
// as NaN, so the format is checked before it is parsed
const DurationFormat = /^\d+(\.\d+)? +(second|minute|hour|day|week|month|year)s?$/

/**
 * Parses a duration such as "90 seconds" or "24 hours" to milliseconds.
 *
 * @param value The duration
 * @returns The duration in milliseconds, or undefined if it is not a duration
 * with a unit itty-time recognises
 */
const durationMs = (value: string): number | undefined => {
	if (!DurationFormat.test(value)) {
		return undefined
	}

	const duration = ms(value)
	return Number.isFinite(duration) && duration >= 0 ? duration : undefined
}

// a duration, such as "90 seconds" or "24 hours", parsed to milliseconds and
// then checked by `allowed`, which reports `message` when it is not allowed
const Duration = (allowed: (duration: number) => boolean, message: string) => RequiredString.transform((v, ctx): number => {
	const duration = durationMs(v)
	if (duration === undefined || !allowed(duration)) {
		ctx.issues.push({ code: "custom", message, input: v })
		return z.NEVER
	}

	return duration
})

/** The shortest lifetime of a user certificate, in seconds, as the API also requires of a requested lifetime */
export const MinUserCertificateLifetime = 5 * 60

/** The shortest lifetime of a host certificate, in seconds, as the API also requires of a requested lifetime */
export const MinHostCertificateLifetime = 24 * 60 * 60

/**
 * The longest clock skew allowed for proofs of possession, in milliseconds.
 * The skew applies on both sides of the CA's clock, so a proof can be used
 * for up to twice this long.
 */
export const MaxRequestTimeSkew = 5 * 60 * 1000

// the number of whole seconds in a duration in milliseconds, or undefined
// when it is not a whole number of seconds. A duration with a fraction, such
// as "1.5 minutes", can be a whole number of seconds give or take rounding
const wholeSeconds = (duration: number): number | undefined => {
	const seconds = Math.round(duration / 1000)
	return Math.abs(duration / 1000 - seconds) < 1e-6 ? seconds : undefined
}

// the lifetime of a certificate, in whole seconds of at least `min` seconds
const Lifetime = (min: number, minDescription: string) => Duration(
	(duration) => (wholeSeconds(duration) ?? 0) >= min,
	`must be a duration of at least ${minDescription}, in whole seconds, such as "30 days"`,
).transform((duration): number => wholeSeconds(duration) ?? 0)

// the clock skew allowed for proofs of possession, see MaxRequestTimeSkew
const RequestTimeSkew = Duration(
	(duration) => duration > 0 && duration <= MaxRequestTimeSkew,
	"must be a positive duration of at most 5 minutes, such as \"90 seconds\"",
)

// an SQLite date modifier for a positive period, such as "1 year" or "90 days"
const RetentionPeriodFormat = /^\+?(\d+(\.\d+)?) (second|minute|hour|day|month|year)s?$/

/**
 * How long certificates are kept after they expire, either "infinite" or a
 * positive period in the format of an SQLite date modifier such as "1 year".
 */
export const RetentionString = z.string().refine((v) => {
	if (v === "infinite") {
		return true
	}

	const amount = RetentionPeriodFormat.exec(v)?.[1]
	return amount !== undefined && Number(amount) > 0
}, { message: "must be \"infinite\" or a positive period such as \"1 year\"" })

// how long certificates are kept, see RetentionString
const RetentionSetting = RetentionString.transform((v): Retention => v === "infinite" ? { kind: "infinite" } : { kind: "period", modifier: v })

/** A boolean set as the string "true" or "false" */
export const BooleanString = z.enum(["true", "false"], { message: "must be \"true\" or \"false\"" })

// whether the host of a URL is the local machine, which is reached without
// crossing a network an attacker could be on
const isLoopbackHost = (hostname: string): boolean =>
	hostname === "localhost" || hostname === "[::1]" || /^127\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(hostname)

/**
 * An https URL, or an http URL for the local machine (`localhost`,
 * `127.0.0.0/8` or `[::1]`), such as a test identity provider. Anything that
 * authenticates requesters is fetched over https elsewhere, so it cannot be
 * changed on its way to the CA.
 */
export const HttpsOrLoopbackUrl = z.url({ protocol: /^https?$/, message: "must be an https URL" })
	.refine((v) => {
		// a value that is not a URL at all is reported by z.url, which does not
		// stop this check from running
		if (!URL.canParse(v)) {
			return true
		}

		const url = new URL(v)
		return url.protocol === "https:" || isLoopbackHost(url.hostname)
	}, { message: "must be an https URL, or an http URL for localhost" })

/** The levels the CA can log at */
export const LogLevelName = z.enum(["none", "error", "warning", "info", "debug"])

/**
 * The algorithms a JWT may be signed with, for requester and proxy JWTs alike.
 * Only asymmetric algorithms are allowed, as the keys come from a public JWKS.
 */
export const JwtAlgorithms = ["RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512", "EdDSA", "Ed25519"] as const

// the entries of a list, trimmed so a space after a comma is allowed
const listEntries = (v: string | string[]): string[] => (typeof v === "string" ? v.split(",") : v).map((entry) => entry.trim())

const EmptyEntryMessage = "must be a comma separated list without empty entries"

// a list, either as a comma separated string or as an array, which must have
// at least one entry, whose entries are trimmed and must not be empty
const NonEmptyList = z.union([z.string(), z.array(z.string())], { message: "must be set" }).transform((v, ctx): string[] => {
	const entries = listEntries(v)
	if (entries.length === 0 || (entries.length === 1 && entries[0] === "")) {
		ctx.issues.push({ code: "custom", message: "must be set", input: v })
		return z.NEVER
	}
	if (entries.some((entry) => entry === "")) {
		ctx.issues.push({ code: "custom", message: EmptyEntryMessage, input: v })
		return z.NEVER
	}

	return entries
})

// a list of the algorithms a JWT may be signed with, see JwtAlgorithms
const JwtAlgorithmList = NonEmptyList.superRefine((entries, ctx) => {
	for (const entry of entries) {
		if (!(JwtAlgorithms as readonly string[]).includes(entry)) {
			ctx.issues.push({ code: "custom", message: `"${entry}" is not one of ${JwtAlgorithms.join(", ")}`, input: entries })
		}
	}
})

// an optional list, either as a comma separated string or as an array, whose
// entries are trimmed and must not be empty. A list that is not set, or is an
// empty string (as an unset var may be on Workers), has no entries
const List = z.union([z.string(), z.array(z.string())]).optional().transform((v, ctx): string[] => {
	if (v === undefined || v === "") {
		return []
	}

	const entries = listEntries(v)
	if (entries.some((entry) => entry === "")) {
		ctx.issues.push({ code: "custom", message: EmptyEntryMessage, input: v })
		return z.NEVER
	}

	return entries
})

// reports each entry of a list of user certificate principals that cannot be
// on a certificate
const checkPrincipals = (principals: string[], ctx: z.RefinementCtx): void => {
	for (const principal of principals) {
		const issue = principalIssue("user", principal)
		if (issue !== undefined) {
			ctx.issues.push({ code: "custom", message: issue, input: principal })
		}
	}
}

// a list of principals added to every user certificate, each of which must be
// allowed by principalIssue
const PrincipalList = List.superRefine(checkPrincipals)

// reports each extension name that is not one word, as the name of an SSH
// certificate extension cannot contain whitespace and a comma separates them
const checkExtensions = (extensions: string[], ctx: z.RefinementCtx): void => {
	for (const extension of extensions) {
		if (/[\s,]/.test(extension)) {
			ctx.issues.push({ code: "custom", message: `extension "${extension}" must not contain whitespace or commas`, input: extension })
		}
	}
}

// the extensions included in user certificates by default
const ExtensionList = List.superRefine(checkExtensions)

// a flag, either as a boolean or as the string "true" or "false"
const Flag = z.union([z.boolean(), BooleanString]).optional().transform((v): boolean => v === true || v === "true")

/**
 * An admin setting that may be left unset, which is unset when it is missing
 * or an empty string (as an unset var may be on Workers), and otherwise must
 * be valid according to `schema`.
 */
export const OptionalSetting = <T extends z.ZodType>(schema: T) => z.preprocess((v) => v === "" ? undefined : v, schema.optional())

/** An https URL */
export const HttpsUrl = z.url({ protocol: /^https$/, message: "must be an https URL" })

// the characters of an HTTP header name, a token in RFC 9110
const HeaderNameFormat = /^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$/

/** The name of an HTTP header */
export const HeaderNameString = z.string().regex(HeaderNameFormat, { message: "must be an HTTP header name" })

// a host name made of DNS labels, without a scheme, port or path
const HostnameFormat = /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$/i

/** A host name, such as "ssh-ca.example.com", without a scheme, port or path */
export const HostnameString = z.string().regex(HostnameFormat, { message: "must be a host name such as \"ssh-ca.example.com\"" })



/**
 * Who may use the admin UI, from the settings that say which emails and
 * roles are admins.
 */
export interface AdminAllowlist {
	/** The emails of admins, lowercased, as emails are compared case-insensitively */
	emails: string[]
	/** The roles that make someone an admin and the claim of the proxy JWT that holds them, when roles are used */
	roles: { claim: string, allowed: string[] } | undefined
}

/**
 * The settings of the admin UI, which is only turned on once every setting it
 * needs is set, see ADR-0002.
 *
 * - `disabled`: none of the `ADMIN_*` settings are set
 * - `partial`: some are set, but not enough to turn the admin UI on, and `missing` names those still needed
 * - `enabled`: the admin UI is on
 */
export type AdminConfig =
	| { kind: "disabled" }
	| { kind: "partial", missing: string[] }
	| {
		kind: "enabled"
		/** The request header the proxy sends its JWT in */
		header: string
		/** The https URL of the proxy's JWKS */
		jwksUrl: string
		/** The issuer the proxy JWT must have */
		issuer: string
		/** The audiences the proxy JWT may be issued for, at least one */
		audience: string[]
		/** The algorithms the proxy JWT may be signed with */
		algorithms: string[]
		/** Who is an admin */
		allowlist: AdminAllowlist
		/** The only host name the admin UI answers on, lowercased, when it is limited to one */
		hostname: string | undefined
	}

// the admin settings once each has been validated, where undefined means
// the setting is not set
type AdminSettings = {
	ADMIN_JWT_HEADER?: string | undefined
	ADMIN_JWKS_URL?: string | undefined
	ADMIN_JWT_ISSUER?: string | undefined
	ADMIN_JWT_AUD?: string[] | undefined
	ADMIN_JWT_ALGORITHMS?: string[] | undefined
	ADMIN_ALLOWED_EMAILS?: string[] | undefined
	ADMIN_ALLOWED_ROLES?: string[] | undefined
	ADMIN_JWT_ROLES_CLAIM?: string | undefined
	ADMIN_HOSTNAME?: string | undefined
}

/**
 * Decides whether the admin UI is turned on from its validated settings, see
 * {@link AdminConfig}.
 *
 * @param env The admin settings, already validated
 * @returns The settings of the admin UI
 */
const adminConfig = (env: AdminSettings): AdminConfig => {
	if (Object.values(env).every((v) => v === undefined)) {
		return { kind: "disabled" }
	}

	const missing: string[] = []
	const { ADMIN_JWT_HEADER: header, ADMIN_JWKS_URL: jwksUrl, ADMIN_JWT_ISSUER: issuer, ADMIN_JWT_AUD: audience } = env
	if (header === undefined) {
		missing.push("ADMIN_JWT_HEADER")
	}
	if (jwksUrl === undefined) {
		missing.push("ADMIN_JWKS_URL")
	}
	if (issuer === undefined) {
		missing.push("ADMIN_JWT_ISSUER")
	}
	if (audience === undefined) {
		missing.push("ADMIN_JWT_AUD")
	}

	// roles are only used when the claim holding them is set too
	const roles = env.ADMIN_ALLOWED_ROLES !== undefined && env.ADMIN_JWT_ROLES_CLAIM !== undefined
		? { claim: env.ADMIN_JWT_ROLES_CLAIM, allowed: env.ADMIN_ALLOWED_ROLES }
		: undefined
	const emails = env.ADMIN_ALLOWED_EMAILS
	if (emails === undefined && roles === undefined) {
		if (env.ADMIN_ALLOWED_ROLES !== undefined) {
			missing.push("ADMIN_JWT_ROLES_CLAIM")
		} else if (env.ADMIN_JWT_ROLES_CLAIM !== undefined) {
			missing.push("ADMIN_ALLOWED_ROLES")
		} else {
			missing.push("ADMIN_ALLOWED_EMAILS or ADMIN_ALLOWED_ROLES with ADMIN_JWT_ROLES_CLAIM")
		}
	}

	if (header === undefined || jwksUrl === undefined || issuer === undefined || audience === undefined || missing.length > 0) {
		return { kind: "partial", missing }
	}

	return {
		kind: "enabled",
		header,
		jwksUrl,
		issuer,
		audience,
		algorithms: env.ADMIN_JWT_ALGORITHMS ?? ["RS256"],
		allowlist: {
			emails: (emails ?? []).map((email) => email.toLowerCase()),
			roles,
		},
		hostname: env.ADMIN_HOSTNAME?.toLowerCase(),
	}
}

/**
 * How long certificates are kept in the database after they expire.
 *
 * - `infinite`: certificates are never removed
 * - `period`: certificates are removed once they have been expired for longer than `modifier`, an SQLite date modifier such as "1 year"
 */
export type Retention =
	| { kind: "infinite" }
	| { kind: "period", modifier: string }

// the configuration values of SshCaBindings, each validated and parsed into
// the type the CA uses. The database, private key, rate limiter and cache are
// objects provided by the runtime, so are used as they are
const ConfigFields = z.object({
	ISSUER_DN: RequiredString,
	JWT_JWKS_URL: HttpsOrLoopbackUrl,
	JWT_ISSUER: RequiredString,
	JWT_ALGORITHMS: JwtAlgorithmList,
	JWT_AUD: NonEmptyList,
	JWT_ACCESS_TOKEN_AUD: List,
	OIDC_USERINFO_URL: OptionalSetting(HttpsOrLoopbackUrl),
	JWT_SSH_CERTIFICATE_PRINCIPALS_CLAIM: RequiredString,
	CERTIFICATE_REQUEST_TIME_SKEW_MAX: RequestTimeSkew,
	SSH_CERTIFICATE_EXTENSIONS: ExtensionList,
	SSH_CERTIFICATE_INCLUDE_SELF: Flag,
	SSH_CERTIFICATE_INCLUDE_SELF_EMAIL: Flag,
	SSH_CERTIFICATE_LIFETIME: Lifetime(MinUserCertificateLifetime, "5 minutes"),
	SSH_CERTIFICATE_PRINCIPALS: PrincipalList,
	SSH_HOST_CERTIFICATE_ALLOWED_EMAILS: List,
	SSH_HOST_CERTIFICATE_ALLOWED_ROLES: List,
	SSH_HOST_CERTIFICATE_LIFETIME: Lifetime(MinHostCertificateLifetime, "24 hours"),
	DB_CERTIFICATE_RETENTION: RetentionSetting,
	LOG_LEVEL: LogLevelName.optional(),
	LANDING_PAGE: Flag,
	// the admin settings may each be missing, which turns the admin UI off,
	// but any that are set must be valid
	ADMIN_JWT_HEADER: OptionalSetting(HeaderNameString),
	ADMIN_JWKS_URL: OptionalSetting(HttpsUrl),
	ADMIN_JWT_ISSUER: OptionalSetting(RequiredString),
	ADMIN_JWT_AUD: OptionalSetting(NonEmptyList),
	ADMIN_JWT_ALGORITHMS: OptionalSetting(JwtAlgorithmList),
	ADMIN_ALLOWED_EMAILS: OptionalSetting(NonEmptyList),
	ADMIN_ALLOWED_ROLES: OptionalSetting(NonEmptyList),
	ADMIN_JWT_ROLES_CLAIM: OptionalSetting(RequiredString),
	ADMIN_HOSTNAME: OptionalSetting(HostnameString),
})

/**
 * The names of the configuration values in {@link SshCaBindings}, which are
 * also the names of the environment variables read by `bindingsFromEnv`.
 */
export const ConfigNames = Object.keys(ConfigFields.shape)

/**
 * The configuration values of {@link SshCaBindings}, validated and parsed into
 * the types the CA uses.
 */
const ConfigSchema = ConfigFields.transform((env) => ({
	issuerDn: env.ISSUER_DN,
	jwksUrl: env.JWT_JWKS_URL,
	issuer: env.JWT_ISSUER,
	algorithms: env.JWT_ALGORITHMS,
	audience: env.JWT_AUD,
	accessTokenAudience: env.JWT_ACCESS_TOKEN_AUD,
	userinfoUrl: env.OIDC_USERINFO_URL,
	principalsClaim: env.JWT_SSH_CERTIFICATE_PRINCIPALS_CLAIM,
	/** The clock skew allowed for proofs of possession and certificates, in milliseconds */
	requestTimeSkewMax: env.CERTIFICATE_REQUEST_TIME_SKEW_MAX,
	extensions: env.SSH_CERTIFICATE_EXTENSIONS,
	includeSelf: env.SSH_CERTIFICATE_INCLUDE_SELF,
	includeSelfEmail: env.SSH_CERTIFICATE_INCLUDE_SELF_EMAIL,
	/** The maximum lifetime of a user certificate, in seconds */
	certificateLifetime: env.SSH_CERTIFICATE_LIFETIME,
	principals: env.SSH_CERTIFICATE_PRINCIPALS,
	/** The emails of requesters who may request host certificates, lowercased, as emails are compared case-insensitively */
	hostAllowedEmails: env.SSH_HOST_CERTIFICATE_ALLOWED_EMAILS.map((email) => email.toLowerCase()),
	/**
	 * The roles that may request host certificates, with spaces replaced by
	 * underscores, as they are in the principals claim they are compared with
	 */
	hostAllowedRoles: env.SSH_HOST_CERTIFICATE_ALLOWED_ROLES.map((role) => role.replaceAll(" ", "_")),
	/** The maximum lifetime of a host certificate, in seconds */
	hostCertificateLifetime: env.SSH_HOST_CERTIFICATE_LIFETIME,
	retention: env.DB_CERTIFICATE_RETENTION,
	/** Whether the landing page is served at `/` */
	landingPage: env.LANDING_PAGE,
	admin: adminConfig({
		ADMIN_JWT_HEADER: env.ADMIN_JWT_HEADER,
		ADMIN_JWKS_URL: env.ADMIN_JWKS_URL,
		ADMIN_JWT_ISSUER: env.ADMIN_JWT_ISSUER,
		ADMIN_JWT_AUD: env.ADMIN_JWT_AUD,
		ADMIN_JWT_ALGORITHMS: env.ADMIN_JWT_ALGORITHMS,
		ADMIN_ALLOWED_EMAILS: env.ADMIN_ALLOWED_EMAILS,
		ADMIN_ALLOWED_ROLES: env.ADMIN_ALLOWED_ROLES,
		ADMIN_JWT_ROLES_CLAIM: env.ADMIN_JWT_ROLES_CLAIM,
		ADMIN_HOSTNAME: env.ADMIN_HOSTNAME,
	}),
}))

/**
 * The CA's configuration, parsed from {@link SshCaBindings} by {@link caConfig}.
 */
export type CaConfig = z.infer<typeof ConfigSchema>

/**
 * The result of parsing the configuration in a set of bindings.
 */
export type ConfigResult =
	| { success: true, config: CaConfig }
	| { success: false, error: InvalidConfigurationError }

/**
 * Formats the issues with a configuration, in the same format for every
 * runtime.
 *
 * @param error The error from validating the configuration
 * @returns The error to report
 */
export const configurationError = (error: z.ZodError): InvalidConfigurationError => {
	return new InvalidConfigurationError(`invalid configuration:\n${z.prettifyError(error)}`)
}

// the parsed configuration of each set of bindings, so the bindings are only
// parsed once however many times their configuration is used
const parsed = new WeakMap<SshCaBindings, ConfigResult>()

/**
 * Validates and parses the configuration in a set of bindings, see
 * {@link CaConfig}. Each set of bindings is parsed once, and the same result
 * is returned for it after that.
 *
 * @param env The bindings of the CA
 * @returns The parsed configuration, or why it is not valid
 */
export const parseConfig = (env: SshCaBindings): ConfigResult => {
	const cached = parsed.get(env)
	if (cached !== undefined) {
		return cached
	}

	const result = ConfigSchema.safeParse(env)
	const config: ConfigResult = result.success
		? { success: true, config: result.data }
		: { success: false, error: configurationError(result.error) }

	parsed.set(env, config)

	return config
}

/**
 * Returns the parsed configuration in a set of bindings, see
 * {@link parseConfig}.
 *
 * @param env The bindings of the CA
 * @returns The parsed configuration
 * @throws {@link InvalidConfigurationError} if the configuration is not valid
 */
export const caConfig = (env: SshCaBindings): CaConfig => {
	const result = parseConfig(env)
	if (!result.success) {
		throw result.error
	}

	return result.config
}
