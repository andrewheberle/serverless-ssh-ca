import { dbCleanup } from "./db"
import { app } from "./router"

export default {
    fetch: app.fetch,
    async scheduled(controller: ScheduledController, env: Env, ctx: ExecutionContext) {
        ctx.waitUntil(dbCleanup())
    },
} satisfies ExportedHandler<Env>
