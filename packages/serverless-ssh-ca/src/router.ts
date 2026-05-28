import { fromHono } from "chanfana"
import { Hono, type Context } from "hono"
import { createApi as apiv3 } from "./api/v3"
import { HTTPException } from "hono/http-exception"
import { logger } from "./logger"
import type { SshCaBindings } from "./types"

export type CFArgs = [SshCaBindings, ExecutionContext]
export type AppContext = Context<{ Bindings: SshCaBindings }>

export const createApp = (env: SshCaBindings) => {
    const hono = new Hono()

    // add error handling
    hono.onError((err, c) => {
        if (err instanceof HTTPException) {
            return err.getResponse()
        }

        logger(env).error("unexpected error from router", "error", err)
        return c.json({ success: false, errors: [{ code: 7000, message: "Internal Server Error" }] }, 500)
    })

    const app = fromHono(hono)

    app.registry.registerComponent("securitySchemes", "oidcAuth", {
        type: 'http',
        scheme: 'bearer',
        bearerFormat: 'JWT',
    })

    app.route("/api/v3", apiv3(env))

    return app
}
