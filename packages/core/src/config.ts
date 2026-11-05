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
 * @param allowZero Whether the duration may be zero
 * @returns The duration in milliseconds, or undefined if it is not a duration
 * with a unit itty-time recognises or is not positive (or zero when allowed)
 */
const durationMs = (value: string, allowZero: boolean): number | undefined => {
	if (!DurationFormat.test(value)) {
		return undefined
	}

	const duration = ms(value)
	if (!Number.isFinite(duration) || duration < 0 || (!allowZero && duration === 0)) {
		return undefined
	}

	return duration
}

const durationMessage = (allowZero: boolean): string => allowZero
	? "must be a duration such as \"90 seconds\""
	: "must be a positive duration such as \"24 hours\""

/**
 * A duration in the format accepted by itty-time, such as "90 seconds" or
 * "24 hours", which must have a unit and may only be zero when `allowZero` is
 * set.
 */
export const DurationString = (opts: { allowZero: boolean }) => RequiredString.refine(
	(v) => durationMs(v, opts.allowZero) !== undefined,
	{ message: durationMessage(opts.allowZero) },
)

// a duration, see DurationString, parsed to milliseconds
const Duration = (opts: { allowZero: boolean }) => RequiredString.transform((v, ctx): number => {
	const duration = durationMs(v, opts.allowZero)
	if (duration === undefined) {
		ctx.issues.push({ code: "custom", message: durationMessage(opts.allowZero), input: v })
		return z.NEVER
	}

	return duration
})

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

/** An http or https URL */
export const HttpUrl = z.url({ protocol: /^https?$/, message: "must be an http or https URL" })

/** The levels the CA can log at */
export const LogLevelName = z.enum(["none", "error", "warning", "info", "debug"])

// a list, either as a comma separated string or as an array
const List = z.union([z.string(), z.array(z.string())]).optional().transform((v): string[] => {
	if (v === undefined || v === "") {
		return []
	}

	return typeof v === "string" ? v.split(",") : v
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

/**
 * A comma separated list of principals added to every user certificate, each
 * of which must be allowed by {@link principalIssue}. Entries are not
 * trimmed, so a space after a comma is refused.
 */
export const PrincipalListString = z.string().optional().superRefine((v, ctx) => {
	if (v !== undefined && v !== "") {
		checkPrincipals(v.split(","), ctx)
	}
})

// a list of principals added to every user certificate, see PrincipalListString
const PrincipalList = List.superRefine(checkPrincipals)

// a list that must have at least one entry
const RequiredList = z.union([RequiredString, z.array(RequiredString).min(1, { message: "must be set" })])
	.transform((v): string[] => typeof v === "string" ? v.split(",") : v)

// a flag, either as a boolean or as the string "true" or "false"
const Flag = z.union([z.boolean(), BooleanString]).optional().transform((v): boolean => v === true || v === "true")

/**
 * How long certificates are kept in the database after they expire.
 *
 * - `infinite`: certificates are never removed
 * - `period`: certificates are removed once they have been expired for longer than `modifier`, an SQLite date modifier such as "1 year"
 */
export type Retention =
	| { kind: "infinite" }
	| { kind: "period", modifier: string }

/**
 * The configuration values of {@link SshCaBindings}, validated and parsed into
 * the types the CA uses. The database, private key, rate limiter and cache are
 * objects provided by the runtime, so are used as they are.
 */
const ConfigSchema = z.object({
	ISSUER_DN: RequiredString,
	JWT_JWKS_URL: HttpUrl,
	JWT_ISSUER: RequiredString,
	JWT_ALGORITHMS: RequiredList,
	// a missing audience is reported when a token is verified, so it fails
	// closed without being refused here, see MissingAudienceError
	JWT_AUD: List,
	JWT_ACCESS_TOKEN_AUD: List,
	// an empty string is the same as not set, as it may be on Workers
	OIDC_USERINFO_URL: z.union([z.literal(""), HttpUrl]).optional().transform((v) => v === "" ? undefined : v),
	JWT_SSH_CERTIFICATE_PRINCIPALS_CLAIM: RequiredString,
	CERTIFICATE_REQUEST_TIME_SKEW_MAX: Duration({ allowZero: true }),
	SSH_CERTIFICATE_EXTENSIONS: List,
	SSH_CERTIFICATE_INCLUDE_SELF: Flag,
	SSH_CERTIFICATE_INCLUDE_SELF_EMAIL: Flag,
	SSH_CERTIFICATE_LIFETIME: Duration({ allowZero: false }),
	SSH_CERTIFICATE_PRINCIPALS: PrincipalList,
	SSH_HOST_CERTIFICATE_ALLOWED_EMAILS: List,
	SSH_HOST_CERTIFICATE_ALLOWED_ROLES: List,
	SSH_HOST_CERTIFICATE_LIFETIME: Duration({ allowZero: false }),
	DB_CERTIFICATE_RETENTION: RetentionSetting,
	LOG_LEVEL: LogLevelName.optional(),
}).transform((env) => ({
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
	certificateLifetime: env.SSH_CERTIFICATE_LIFETIME / 1000,
	principals: env.SSH_CERTIFICATE_PRINCIPALS,
	hostAllowedEmails: env.SSH_HOST_CERTIFICATE_ALLOWED_EMAILS,
	hostAllowedRoles: env.SSH_HOST_CERTIFICATE_ALLOWED_ROLES,
	/** The maximum lifetime of a host certificate, in seconds */
	hostCertificateLifetime: env.SSH_HOST_CERTIFICATE_LIFETIME / 1000,
	retention: env.DB_CERTIFICATE_RETENTION,
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
