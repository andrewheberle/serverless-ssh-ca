import { fromHono } from "chanfana"
import { Hono, type Context } from "hono"
import { api as apiv1 } from "./api/v1"
import { api as apiv2 } from "./api/v2"
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

    // workaround as chanfana bundles its own HTTPException - instanceof fails
    if (typeof (err as HTTPException).getResponse === "function") {
        const e = err as HTTPException
        const message = e.message === "" ? "HTTPException" : e.message

        if (e.cause !== undefined) {
            logger.error(message, "status", e.status,"error", e.cause)
        } else {
            logger.error(message,  "status", e.status, "error", "undefined")
        }
        return e.getResponse()
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

openapi.route("/api/v1", apiv1)
openapi.route("/api/v2", apiv2)
