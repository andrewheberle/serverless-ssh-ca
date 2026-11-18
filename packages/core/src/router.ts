import { ApiException, fromHono, NotFoundException, TooManyRequestsException } from "chanfana"
import { AdminBasePath, createAdminApp } from "./admin/index.js"
import { createLandingApp } from "./landing/index.js"
import { Hono, type Context } from "hono"
import { BasePath as v4BasePath, createApi as apiv4 } from "./api/v4/index.js"
import { HTTPException } from "hono/http-exception"
import { logger } from "./logger.js"
import { errorResponse, internalServerErrorResponse } from "./errors.js"
import { docsSecurityHeaders, noSniff } from "./web/docs.js"
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
/**
 * The version of the API, published as `info.version` in `openapi.json`. It is
 * versioned separately from the package, following semver for what clients
 * can observe:
 *
 * - major: a breaking change, which also needs a major release of the package
 * - minor: something added, such as an operation, a response or an optional field
 * - patch: a change to descriptions, or a change oasdiff reports as breaking
 *   that is compatible on the wire and acknowledged in `.oasdiff-err-ignore`
 *
 * Bump it in the same change as `openapi.json`. Operation IDs and component
 * names are part of the contract, as clients generate code from them, so they
 * are pinned by `tests/openapi-names.test.ts`.
 */
export const ApiVersion = "4.0.1"

export const ApiV3RemovedMessage = "API v3 was removed in serverless-ssh-ca 1.0.0; upgrade ssh-ca-client to 0.24.0 or later"

// thrown for API v3 paths, which are answered with a 410 and the message above
class ApiV3RemovedException extends ApiException {
    override isVisible = true
    override default_message = ApiV3RemovedMessage
    override status = 410
    override code = 410
}

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
    const apiV3Removed = (): never => {
        throw new ApiV3RemovedException()
    }
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
            throw new TooManyRequestsException()
        }

        return await next()
    })

    // errors are thrown as chanfana's exceptions and formatted as the API's
    // routes format them, so every error response has the same shape
    hono.onError((err) => {
        if (err instanceof HTTPException) {
            return err.getResponse()
        }

        if (err instanceof ApiException) {
            return errorResponse(err)
        }

        logger(env).error("unexpected error from router", "error", err)
        return internalServerErrorResponse()
    })

    // a request under /api/ that matches no route, including a known path with
    // the wrong method, is answered with the API's JSON error body rather than
    // Hono's plain text, so a client can tell it from a 404 for a certificate
    // by its message. Everything else keeps Hono's default
    hono.notFound((c) => {
        if (c.req.path.startsWith("/api/")) {
            return errorResponse(new NotFoundException("not found"))
        }

        return c.text("404 Not Found", 404)
    })

    // the API docs: Swagger UI at /docs and the schema at /openapi.json, both
    // served by chanfana. ReDoc is turned off below, and the YAML schema,
    // which chanfana serves with the JSON one, is answered with a 404 here,
    // as neither is documented and every page served shares the admin UI's
    // origin (#611)
    hono.use("/docs", docsSecurityHeaders())
    hono.use("/openapi.json", noSniff())
    hono.get("/openapi.yaml", (c) => c.notFound())

    // the admin UI is a plain Hono app, so is not part of the OpenAPI schema
    hono.route(AdminBasePath, createAdminApp(env))

    // the landing page is a plain Hono app too, with routes only for "/" and
    // its stylesheet, and only while it is turned on
    hono.route("/", createLandingApp(env))

    const app = fromHono(hono, {
		redoc_url: null,
		schema: {
			info: {
				title: "Serverless SSH CA API",
				version: ApiVersion
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
