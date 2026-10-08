import type { ExecutionContext } from "hono"
import { dbCleanup } from "./db/index.js"
import { createApp } from "./router.js"
import type { SshCaBindings } from "./types.js"
export type { CaDatabase, CaDatabaseQueryResult, CaDatabaseResult, CaPreparedStatement, CaSecret, SshCaBindings } from "./types.js"

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
 * @returns The CA's request handler and database cleanup task, see {@link SshCa}
 */
export const createSshCa = (env: SshCaBindings): SshCa => {
    const app = createApp(env)

    return {
        fetch: async (req: Request): Promise<Response> => await app.fetch(req, env),
        cleanup: async (): Promise<void> => await dbCleanup(env),
    }
}

let app: ReturnType<typeof createApp> | undefined

export default {
    fetch(req: Request, env: SshCaBindings, ctx: ExecutionContext) {
        if (app === undefined) {
            app = createApp(env)
        }
        return app.fetch(req, env, ctx)
    },
    async scheduled(controller: unknown, env: SshCaBindings, ctx: ExecutionContext) {
        ctx.waitUntil(dbCleanup(env))
    },
} satisfies SshCaHandler
