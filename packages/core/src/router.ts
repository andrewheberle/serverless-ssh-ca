import { fromHono } from "chanfana"
import { Hono, type Context } from "hono"
import { createApi as apiv3 } from "./api/v3/index.js"
import { BasePath as v4BasePath, createApi as apiv4 } from "./api/v4/index.js"
import { HTTPException } from "hono/http-exception"
import { logger } from "./logger.js"
import { TooManyRequestsException } from "chanfana"
import type { SshCaBindings } from "./types.js"

export type AppContext = Context<{ Bindings: SshCaBindings }>

/**
 * Returns the key a request is rate limited by, or undefined if the request
 * should not be rate limited.
 */
export type RateLimitKey = (req: Request) => string | undefined

/**
 * Options for the CA that are not part of its bindings.
 */
export interface SshCaOptions {
    /**
     * Returns the key requests are rate limited by when `RATE_LIMITER` is
     * set. Defaults to the client IP address in the `CF-Connecting-IP` header,
     * which is set by Cloudflare, so other runtimes should provide one that
     * suits their limiter, for example using a header set by a reverse proxy.
     */
    rateLimitKey?: RateLimitKey
}

/**
 * Returns the client IP address set by Cloudflare in the `CF-Connecting-IP`
 * header, which is the default key requests are rate limited by.
 */
export const cloudflareClientIp: RateLimitKey = (req) => req.headers.get("CF-Connecting-IP") ?? undefined

// requests that only read from the CA, which are not rate limited
const ReadMethods = new Set(["GET", "HEAD", "OPTIONS"])

export const createApp = (env: SshCaBindings, options: SshCaOptions = {}) => {
    const hono = new Hono<{ Bindings: SshCaBindings }>()
    const rateLimitKey = options.rateLimitKey ?? cloudflareClientIp

    // limit requests to issue, renew and revoke certificates
    hono.use("/api/*", async (c, next) => {
        const limiter = c.env.RATE_LIMITER
        if (limiter === undefined || ReadMethods.has(c.req.method)) {
            return await next()
        }

        const l = logger(env).with("in", "rateLimit")
        const key = rateLimitKey(c.req.raw)
        if (key === undefined) {
            l.debug("no rate limit key for request")
            return await next()
        }

        let success: boolean
        try {
            success = (await limiter.limit({ key })).success
        } catch (err) {
            // a failing limiter must not stop certificates being issued or revoked
            l.error("rate limiter failed", "error", err)
            return await next()
        }

        if (!success) {
            l.warn("request was rate limited", "key", key, "method", c.req.method, "path", c.req.path)
            const err = new TooManyRequestsException()
            return c.json({ success: false, errors: err.buildResponse(), result: {} }, 429)
        }

        return await next()
    })

    // add error handling
    hono.onError((err, c) => {
        if (err instanceof HTTPException) {
            return err.getResponse()
        }

        logger(env).error("unexpected error from router", "error", err)
        return c.json({ success: false, errors: [{ code: 7000, message: "Internal Server Error" }] }, 500)
    })

    const app = fromHono(hono, {
		schema: {
			info: {
				title: "Serverless SSH CA API",
				version: "4.0.0"
			},
		}
	})

    app.registry.registerComponent("securitySchemes", "oidcAuth", {
        type: 'http',
        scheme: 'bearer',
        bearerFormat: 'JWT',
    })

    app.route("/api/v3", apiv3(env))
    app.route(v4BasePath, apiv4(env))

    return app
}
