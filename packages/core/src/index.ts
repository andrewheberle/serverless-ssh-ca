import type { ExecutionContext } from "hono"
import { caConfig, InvalidConfigurationError, parseConfig } from "./config.js"
import { dbCleanup } from "./db/index.js"
import { logger } from "./logger.js"
import { createApp, type SshCaOptions } from "./router.js"
import type { SshCaBindings } from "./types.js"
export type { CaCache, CaDatabase, CaDatabaseQueryResult, CaDatabaseResult, CaPreparedStatement, CaRateLimiter, CaSecret, SshCaBindings } from "./types.js"
export { cloudflareClientIp, type RateLimitKey, type SshCaOptions } from "./router.js"
export { InvalidConfigurationError } from "./config.js"

// the handlers the CA exposes, compatible with a Cloudflare Workers ExportedHandler
type SshCaHandler = {
    fetch(req: Request, env: SshCaBindings, ctx: ExecutionContext): Response | Promise<Response>
    scheduled(controller: unknown, env: SshCaBindings, ctx: ExecutionContext): Promise<void>
}

/**
 * A runtime neutral instance of the CA, returned by {@link createSshCa}.
 */
export interface SshCa {
    /**
     * Handle a request to the CA's API, suitable for any server that speaks
     * the Fetch API `Request` and `Response` types.
     */
    fetch(req: Request): Promise<Response>
    /**
     * Remove expired certificates from the database according to
     * `DB_CERTIFICATE_RETENTION`. This should be run periodically (for example
     * once a day), as the `scheduled` handler does on Cloudflare Workers.
     */
    cleanup(): Promise<void>
}

/**
 * Create an instance of the CA bound to a fixed set of bindings, for use on
 * runtimes other than Cloudflare Workers.
 *
 * On Workers use the default export instead, which receives its bindings from
 * the runtime on each request.
 *
 * @param env The bindings (configuration, database and private key) for the CA, see {@link SshCaBindings}
 * @param options Options for the CA, such as the key requests are rate limited by, see {@link SshCaOptions}
 * @returns The CA's request handler and database cleanup task, see {@link SshCa}
 * @throws {@link InvalidConfigurationError} if the configuration in `env` is
 * missing or invalid, or if `RATE_LIMITER` is set without the `rateLimitKey`
 * option
 */
export const createSshCa = (env: SshCaBindings, options: SshCaOptions = {}): SshCa => {
    // refuse an invalid configuration before anything is served with it
    caConfig(env)

    // the default key is a header that only Cloudflare sets, which a client
    // can set itself anywhere else, so the key must be chosen explicitly
    if (env.RATE_LIMITER !== undefined && options.rateLimitKey === undefined) {
        throw new InvalidConfigurationError("invalid configuration:\n✖ the rateLimitKey option must be set when RATE_LIMITER is set, for example to cloudflareClientIp when running behind Cloudflare")
    }

    const app = createApp(env, options)

    return {
        fetch: async (req: Request): Promise<Response> => await app.fetch(req, env),
        cleanup: async (): Promise<void> => await dbCleanup(env),
    }
}

// the bindings whose invalid configuration has been logged, so it is logged
// once rather than for every request
const reported = new WeakSet<SshCaBindings>()

// whether the configuration in a set of bindings is valid, logging why it is
// not the first time it is checked
const isValid = (env: SshCaBindings): boolean => {
    const config = parseConfig(env)
    if (!config.success && !reported.has(env)) {
        reported.add(env)
        logger(env).error("refusing to serve requests as the configuration is invalid", "error", config.error.message)
    }

    return config.success
}

// the app for each set of bindings. Workers passes the same bindings to every
// request an isolate handles, so the app (and the schemas it validates
// requests with) is built once, from the same bindings its handlers read
const apps = new WeakMap<SshCaBindings, ReturnType<typeof createApp>>()

// the response to every request while the configuration is invalid, which
// does not describe the configuration as it is only logged
const invalidConfigurationResponse = (): Response => Response.json(
    { success: false, errors: [{ code: 7000, message: "Internal Server Error" }] },
    { status: 500 },
)

export default {
    fetch(req: Request, env: SshCaBindings, ctx: ExecutionContext) {
        if (!isValid(env)) {
            return invalidConfigurationResponse()
        }

        let app = apps.get(env)
        if (app === undefined) {
            app = createApp(env)
            apps.set(env, app)
        }

        return app.fetch(req, env, ctx)
    },
    async scheduled(controller: unknown, env: SshCaBindings, ctx: ExecutionContext) {
        // cleanup depends on the retention, so is skipped until the
        // configuration is fixed
        if (!isValid(env)) {
            return
        }

        ctx.waitUntil(dbCleanup(env))
    },
} satisfies SshCaHandler
