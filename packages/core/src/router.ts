import { fromHono } from "chanfana"
import { AdminBasePath, createAdminApp } from "./admin/index.js"
import { createLandingApp } from "./landing/index.js"
import { Hono, type Context } from "hono"
import { BasePath as v4BasePath, createApi as apiv4 } from "./api/v4/index.js"
import { HTTPException } from "hono/http-exception"
import { logger } from "./logger.js"
import { TooManyRequestsException } from "chanfana"
import type { SshCaBindings } from "./types.js"
import { clientAddressOf, type ClientAddress, type ClientAddressSource } from "./client-address.js"

/** The values set on the context of each request, see {@link AppContext} */
export type AppVariables = {
    /** The client address of the request, when it is known, see {@link SshCaOptions.clientAddress} */
    clientAddress: ClientAddress | undefined
}

export type AppContext = Context<{ Bindings: SshCaBindings, Variables: AppVariables }>

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
     * set, which `createSshCa` requires when `RATE_LIMITER` is set. Use a
     * value the client cannot set itself, such as a header set by a trusted
     * reverse proxy, or {@link cloudflareClientIp} behind Cloudflare. The
     * Workers default export always uses {@link cloudflareClientIp}.
     */
    rateLimitKey?: RateLimitKey
    /**
     * Returns the client address of a request, which is recorded with the
     * certificates it issues, renews or revokes and shown in the admin UI. Use
     * a value the client cannot set itself, as for `rateLimitKey`. A value
     * that is not an IPv4 or IPv6 address is not recorded. When this is not
     * set, `createSshCa` records no client address, while the Workers default
     * export always uses {@link cloudflareClientIp}.
     */
    clientAddress?: ClientAddressSource
}

/**
 * Returns the client IP address set by Cloudflare in the `CF-Connecting-IP`
 * header, which is the key the Workers default export rate limits requests by.
 * A client can set this header itself unless the request comes through
 * Cloudflare.
 */
export const cloudflareClientIp: RateLimitKey = (req) => req.headers.get("CF-Connecting-IP") ?? undefined

/**
 * The message API v3 paths are answered with, as API v3 was removed because
 * its proofs of possession were not bound to the request they were sent with.
 */
export const ApiV3RemovedMessage = "API v3 was removed in serverless-ssh-ca 1.0.0; upgrade ssh-ca-client to 0.24.0 or later"

// requests that only read from the CA, which are not rate limited
const ReadMethods = new Set(["GET", "HEAD", "OPTIONS"])

export const createApp = (env: SshCaBindings, options: SshCaOptions = {}) => {
    const hono = new Hono<{ Bindings: SshCaBindings, Variables: AppVariables }>()
    const rateLimitKey = options.rateLimitKey ?? cloudflareClientIp
    // whether a request without a rate limit key has been reported, as
    // requests without one are not limited
    let reportedMissingKey = false
    // whether a client address that is not an IP address has been reported
    let reportedInvalidAddress = false

    // API v3 was removed, so its paths are answered before anything else is
    // done for them, such as rate limiting. This is a plain Hono route, so is
    // not part of the OpenAPI schema.
    const apiV3Removed = (c: Context): Response => c.json({ success: false, errors: [{ code: 410, message: ApiV3RemovedMessage }], result: {} }, 410)
    hono.all("/api/v3", apiV3Removed)
    hono.all("/api/v3/*", apiV3Removed)

    // the client address of requests that issue, renew and revoke
    // certificates, which is recorded with them
    hono.use("/api/*", async (c, next) => {
        if (ReadMethods.has(c.req.method)) {
            return await next()
        }

        const result = clientAddressOf(options.clientAddress, c.req.raw)
        switch (result.kind) {
            case "known":
                c.set("clientAddress", result.address)
                break
            case "none":
                break
            case "invalid": {
                const l = logger(env).with("in", "clientAddress")
                if (!reportedInvalidAddress) {
                    reportedInvalidAddress = true
                    l.warn("client addresses that are not IP addresses are not recorded", "value", result.value)
                } else {
                    l.debug("client address is not an IP address", "value", result.value)
                }
                break
            }
            default: {
                const unknown: never = result
                throw new Error(`unknown client address ${JSON.stringify(unknown)}`)
            }
        }

        return await next()
    })

    // limit requests to issue, renew and revoke certificates
    hono.use("/api/*", async (c, next) => {
        const limiter = c.env.RATE_LIMITER
        if (limiter === undefined || ReadMethods.has(c.req.method)) {
            return await next()
        }

        const l = logger(env).with("in", "rateLimit")
        const key = rateLimitKey(c.req.raw)
        if (key === undefined) {
            if (!reportedMissingKey) {
                reportedMissingKey = true
                l.warn("requests without a rate limit key are not rate limited", "method", c.req.method, "path", c.req.path)
            } else {
                l.debug("no rate limit key for request")
            }
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

    // the admin UI is a plain Hono app, so is not part of the OpenAPI schema
    hono.route(AdminBasePath, createAdminApp(env))

    // the landing page is a plain Hono app too, with routes only for "/" and
    // its stylesheet, and only while it is turned on
    hono.route("/", createLandingApp(env))

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

    app.route(v4BasePath, apiv4(env))

    return app
}
