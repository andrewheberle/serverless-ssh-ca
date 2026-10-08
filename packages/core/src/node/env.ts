import { seconds } from "itty-time"
import z from "zod"
import type { CaDatabase, CaSecret, SshCaBindings } from "../types.js"

const required = z.string().trim().min(1, { message: "must be set" })

// a duration in the format accepted by itty-time, such as "24 hours"
const duration = (opts: { allowZero: boolean }) => required.refine(v => {
	const s = seconds(v)
	return Number.isFinite(s) && (opts.allowZero ? s >= 0 : s > 0)
}, { message: opts.allowZero ? "must be a duration such as \"90 seconds\"" : "must be a positive duration such as \"24 hours\"" })

const boolean = z.enum(["true", "false"], { message: "must be \"true\" or \"false\"" })

/**
 * The environment variables read by {@link bindingsFromEnv}, which match the
 * Workers vars documented for the CA.
 */
export const EnvSchema = z.object({
	DB_CERTIFICATE_RETENTION: z.union([
		z.literal("infinite"),
		// an SQLite date modifier such as "1 year" or "90 days"
		z.string().regex(/^[+-]?\d+(\.\d+)? (second|minute|hour|day|month|year)s?$/),
	], { message: "must be \"infinite\" or a period such as \"1 year\"" }),
	SSH_CERTIFICATE_EXTENSIONS: z.string(),
	SSH_CERTIFICATE_LIFETIME: duration({ allowZero: false }),
	SSH_CERTIFICATE_INCLUDE_SELF: boolean.optional(),
	SSH_CERTIFICATE_INCLUDE_SELF_EMAIL: boolean.optional(),
	SSH_CERTIFICATE_PRINCIPALS: z.string().optional(),
	SSH_HOST_CERTIFICATE_LIFETIME: duration({ allowZero: false }),
	SSH_HOST_CERTIFICATE_ALLOWED_EMAILS: z.string().optional(),
	SSH_HOST_CERTIFICATE_ALLOWED_ROLES: z.string().optional(),
	ISSUER_DN: required,
	JWT_JWKS_URL: z.url({ protocol: /^https?$/, message: "must be an http or https URL" }),
	JWT_AUD: z.string().optional(),
	JWT_ISSUER: required,
	JWT_ALGORITHMS: required,
	JWT_SSH_CERTIFICATE_PRINCIPALS_CLAIM: required,
	CERTIFICATE_REQUEST_TIME_SKEW_MAX: duration({ allowZero: true }),
	LOG_LEVEL: z.enum(["none", "error", "warning", "info", "debug"]).optional(),
})

/**
 * The CA's configuration as read from environment variables, see {@link EnvSchema}.
 */
export type CaEnv = z.infer<typeof EnvSchema>

/**
 * Thrown by {@link bindingsFromEnv} when the environment is not a valid configuration.
 */
export class InvalidConfigurationError extends Error {
	constructor(message: string) {
		super(message)
		this.name = "InvalidConfigurationError"

		Object.setPrototypeOf(this, InvalidConfigurationError.prototype)
	}
}

/**
 * Build the CA's bindings from environment variables, for runtimes where
 * configuration is not supplied as Workers bindings.
 *
 * The variables have the same names and formats as the Workers vars, and are
 * validated before use so that misconfiguration is reported at start up.
 *
 * @example
 * ```ts
 * const env = bindingsFromEnv({
 *     DB: fromNodeSqlite(new DatabaseSync("ssh-ca.sqlite")),
 *     PRIVATE_KEY: secretFromFile("/etc/ssh-ca/ca_key"),
 * })
 * ```
 *
 * @param bindings The database and private key, see {@link CaDatabase} and {@link CaSecret}
 * @param source The environment variables to read, `process.env` by default
 * @returns The bindings to pass to `createSshCa`
 * @throws {@link InvalidConfigurationError} if a variable is missing or invalid
 */
export const bindingsFromEnv = (
	bindings: { DB: CaDatabase, PRIVATE_KEY: CaSecret },
	source: Record<string, string | undefined> = process.env,
): SshCaBindings => {
	const result = EnvSchema.safeParse(source)
	if (!result.success) {
		throw new InvalidConfigurationError(`invalid configuration:\n${z.prettifyError(result.error)}`)
	}

	return { ...result.data, DB: bindings.DB, PRIVATE_KEY: bindings.PRIVATE_KEY }
}
