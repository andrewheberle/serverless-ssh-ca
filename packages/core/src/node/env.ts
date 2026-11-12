import { ConfigNames, InvalidConfigurationError, parseConfig } from "../config.js"
import type { CaCache, CaDatabase, CaRateLimiter, CaSecret, SshCaBindings } from "../types.js"

export { InvalidConfigurationError }

/**
 * Build the CA's bindings from environment variables, for runtimes where
 * configuration is not supplied as Workers bindings.
 *
 * The variables have the same names and formats as the Workers vars, and are
 * validated by the same rules as `createSshCa` uses before they are returned,
 * so that misconfiguration is reported at start up.
 *
 * @example
 * ```ts
 * const env = bindingsFromEnv({
 *     DB: fromNodeSqlite(new DatabaseSync("ssh-ca.sqlite")),
 *     PRIVATE_KEY: secretFromFile("/etc/ssh-ca/ca_key"),
 * })
 * ```
 *
 * @param bindings The database, private key, optional rate limiter and optional cache, see {@link CaDatabase}, {@link CaSecret}, {@link CaRateLimiter} and {@link CaCache}
 * @param source The environment variables to read, `process.env` by default
 * @returns The bindings to pass to `createSshCa`
 * @throws {@link InvalidConfigurationError} if a variable is missing or invalid
 */
export const bindingsFromEnv = (
	bindings: { DB: CaDatabase, PRIVATE_KEY: CaSecret, RATE_LIMITER?: CaRateLimiter, CACHE?: CaCache },
	source: Record<string, string | undefined> = process.env,
): SshCaBindings => {
	const vars: Record<string, string> = {}
	for (const name of ConfigNames) {
		const value = source[name]
		if (value !== undefined) {
			vars[name] = value
		}
	}

	// the vars are only known to have the shape of SshCaBindings once they
	// have been validated below, which throws if they do not
	const env = { ...vars, DB: bindings.DB, PRIVATE_KEY: bindings.PRIVATE_KEY, RATE_LIMITER: bindings.RATE_LIMITER, CACHE: bindings.CACHE } as SshCaBindings
	const result = parseConfig(env)
	if (!result.success) {
		throw result.error
	}

	return env
}
