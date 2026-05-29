import { dbCleanup } from "./db"
import { createApp } from "./router"
import type { SshCaBindings } from "./types"
export type { SshCaBindings } from "./types"

let app: ReturnType<typeof createApp> | undefined

export default {
    fetch(req: Request, env: SshCaBindings, ctx: ExecutionContext) {
        if (app === undefined) {
            app = createApp(env)
        }
        return app.fetch(req, env, ctx)
    },
    async scheduled(controller: ScheduledController, env: SshCaBindings, ctx: ExecutionContext) {
        ctx.waitUntil(dbCleanup(env))
    },
} satisfies ExportedHandler<SshCaBindings>
