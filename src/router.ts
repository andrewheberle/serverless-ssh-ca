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
        if (err.cause !== undefined) {
            logger.error(err.message, "error", err.cause)
        } else {
            logger.error(err.message)
        }
        return err.getResponse()
    } else {
        // an unhandled error should cause a crash
        logger.error("unhandled error", "error", err)
        throw err
    }
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
