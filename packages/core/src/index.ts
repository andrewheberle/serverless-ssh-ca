import type { ExecutionContext } from "hono"
import { dbCleanup } from "./db/index.js"
import { createApp } from "./router.js"
import type { SshCaBindings } from "./types.js"
export type { CaDatabase, CaSecret, SshCaBindings } from "./types.js"

// the handlers the CA exposes, compatible with a Cloudflare Workers ExportedHandler
type SshCaHandler = {
    fetch(req: Request, env: SshCaBindings, ctx: ExecutionContext): Response | Promise<Response>
    scheduled(controller: unknown, env: SshCaBindings, ctx: ExecutionContext): Promise<void>
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
