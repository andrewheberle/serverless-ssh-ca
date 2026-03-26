import { fromHono } from "chanfana"
import { Hono, type Context } from "hono"
import { api as apiv2 } from "./api/v2"
import { api as apiv3 } from "./api/v3"
import { Logger } from "@andrewheberle/ts-slog"
import { HTTPException } from "hono/http-exception"

const logger = new Logger()

export type CFArgs = [Env, ExecutionContext]
export type AppContext = Context<{ Bindings: Env }>

export const app = new Hono()

// add error handling
app.onError((err, c) => {
    if (err instanceof HTTPException) {
        const message = err.message === "" ? "HTTPException" : err.message
        if (err.cause !== undefined) {
            logger.error(message, "status", err.status, "error", err.cause)
        } else {
            logger.error(message, "status", err.status, "error", "undefined")
        }

        return err.getResponse()
    }

    // Handle other errors
    logger.error("unexpected error", "error", err)
    return c.json({ error: "Internal Server Error" }, 500)
})

const openapi = fromHono(app)

export const oidcAuth = openapi.registry.registerComponent(
    "securitySchemes",
    "oidcAuth",
    {
        type: 'http',
        scheme: 'bearer',
        bearerFormat: 'JWT',
    }
)

openapi.route("/api/v2", apiv2)
openapi.route("/api/v3", apiv3)
