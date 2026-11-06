import { Hono, type Context, type MiddlewareHandler } from "hono"
import { html } from "hono/html"
import { HTTPException } from "hono/http-exception"
import { csrf } from "hono/csrf"
import type { ContentfulStatusCode } from "hono/utils/http-status"
import type { JSX } from "hono/jsx/jsx-runtime"
import { caConfig } from "../config.js"
import { certificateStatus, getCertificate, listCertificates } from "../db/index.js"
import { logger } from "../logger.js"
import type { SshCaBindings } from "../types.js"
import { authenticateAdmin, type EnabledAdminConfig } from "./auth.js"
import { CertificateDetailPage, CertificateListPage, ErrorPage, Stylesheet, StylesheetPath } from "./pages.js"
import { CertificateKinds, CertificateListQuery, certificatesLink, certificatesPath, certificateType, SerialString, type CertificateKind } from "./query.js"

/** The path the admin UI is served under */
export const AdminBasePath = "/admin"

/**
 * The headers on every response from the admin UI, including errors and the
 * 404 it answers with while it is turned off.
 */
export const AdminSecurityHeaders: Readonly<Record<string, string>> = {
	"Content-Security-Policy": "default-src 'none'; style-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'",
	"Cache-Control": "no-store",
	"Referrer-Policy": "no-referrer",
	"X-Content-Type-Options": "nosniff",
}

type AdminEnv = {
	Bindings: SshCaBindings
	Variables: {
		/** The email claim of a verified proxy JWT, whether or not it is an admin's */
		email?: string
	}
}

// requests that never change state, which are neither checked for
// cross-site forgery nor rate limited
const SafeMethods = new Set(["GET", "HEAD", "OPTIONS"])

// the bindings whose partial admin configuration has been reported, so it is
// reported once rather than every time an app is created for them
const reportedPartial = new WeakSet<SshCaBindings>()

// the origin requests that change state must come from: the configured host
// name when the admin UI is limited to one, as it is then served behind a
// proxy on https, or otherwise the origin the request was made to
const expectedOrigin = (config: EnabledAdminConfig, c: Context): string => config.hostname !== undefined
	? `https://${config.hostname}`
	: new URL(c.req.url).origin

// the kind of certificate named in a path, if it names one
const certificateKind = (kind: string): CertificateKind | undefined => CertificateKinds.find((k) => k === kind)

// the email of the admin making a request
const adminEmail = (c: Context<AdminEnv>): string => {
	const email = c.get("email")
	if (email === undefined) {
		// the authentication middleware only lets admins through, and
		// always sets their email
		throw new Error("no admin email for an authenticated request")
	}

	return email
}

// renders a page as an HTML document
const page = (c: Context<AdminEnv>, element: JSX.Element, status: ContentfulStatusCode = 200): Response | Promise<Response> => {
	return c.html(html`<!DOCTYPE html>${element}`, status)
}

// sets the security headers on every response, see AdminSecurityHeaders
const securityHeaders: MiddlewareHandler<AdminEnv> = async (c, next) => {
	await next()

	for (const [name, value] of Object.entries(AdminSecurityHeaders)) {
		c.res.headers.set(name, value)
	}
}

/**
 * Creates the admin UI, a plain Hono app (not registered with chanfana, so it
 * is not part of the OpenAPI schema) to be mounted at {@link AdminBasePath}.
 *
 * The admin UI answers every request with 404 unless it is turned on, see
 * {@link AdminConfig}. When it is on, every request must carry a JWT from the
 * identity-aware proxy in front of it that says it is from an admin, see
 * ADR-0002, requests that change state must come from the admin UI's own
 * origin, and are rate limited by `RATE_LIMITER` keyed by the admin's email.
 *
 * @param env The bindings of the CA, whose configuration must be valid
 * @returns The admin UI
 */
export const createAdminApp = (env: SshCaBindings): Hono<AdminEnv> => {
	const app = new Hono<AdminEnv>()
	const config = caConfig(env).admin
	const l = logger(env).with("in", "admin")

	app.onError((err, c) => {
		if (err instanceof HTTPException) {
			return err.getResponse()
		}

		l.error("unexpected error from admin UI", "error", err)
		return c.text("Internal Server Error", 500)
	})

	app.use(securityHeaders)

	switch (config.kind) {
		case "disabled":
			app.use(async (c) => c.notFound())
			return app
		case "partial":
			if (!reportedPartial.has(env)) {
				reportedPartial.add(env)
				l.warn("the admin UI is turned off as some of its settings are missing", "missing", config.missing.join(", "))
			}
			app.use(async (c) => c.notFound())
			return app
		case "enabled":
			return withAdminRoutes(app, env, config)
		default: {
			const unknown: never = config
			throw new Error(`unknown admin configuration ${JSON.stringify(unknown)}`)
		}
	}
}

// adds the middleware and pages of an admin UI that is turned on
const withAdminRoutes = (app: Hono<AdminEnv>, env: SshCaBindings, config: EnabledAdminConfig): Hono<AdminEnv> => {
	const l = logger(env).with("in", "admin")

	// log every request, without the JWT
	app.use(async (c, next) => {
		await next()

		const url = new URL(c.req.url)
		l.info("admin request", "email", c.get("email"), "method", c.req.method, "path", `${url.pathname}${url.search}`, "status", c.res.status)
	})

	// answer on the configured host name only
	app.use(async (c, next) => {
		if (config.hostname !== undefined && new URL(c.req.url).hostname.toLowerCase() !== config.hostname) {
			return c.notFound()
		}

		return await next()
	})

	// refuse cross-site requests that change state. The proxy keeps the
	// admin's session in a cookie, so does not do this itself. Hono's csrf
	// middleware checks the Origin of form submissions, and the check after
	// it also requires Sec-Fetch-Site to be same-origin and the Origin to
	// match whatever the content type
	app.use(csrf({
		origin: (origin, c) => origin === expectedOrigin(config, c),
		// Hono accepts a request when either check passes, so the origin is
		// required here and Sec-Fetch-Site after this
		secFetchSite: () => false,
	}))
	app.use(async (c, next) => {
		if (SafeMethods.has(c.req.method)) {
			return await next()
		}

		if (c.req.header("Sec-Fetch-Site") !== "same-origin" || c.req.header("Origin") !== expectedOrigin(config, c)) {
			return c.text("Forbidden", 403)
		}

		return await next()
	})

	// authenticate and authorise the admin from the proxy's JWT
	app.use(async (c, next) => {
		const auth = await authenticateAdmin(c.req.header(config.header), config, () => {
			l.warn("ignoring the roles claim of the proxy JWT as it is not a string or an array of strings", "claim", config.allowlist.roles?.claim)
		})

		switch (auth.kind) {
			case "unauthenticated":
				l.warn("refusing an admin request without a valid proxy JWT", "reason", auth.reason)
				return c.text("Unauthorized", 401)
			case "forbidden":
				c.set("email", auth.email)
				l.warn("refusing an admin request from someone who is not an admin", "email", auth.email, "reason", auth.reason)
				return c.text("Forbidden", 403)
			case "admin":
				c.set("email", auth.email)
				return await next()
			default: {
				const unknown: never = auth
				throw new Error(`unknown admin authentication ${JSON.stringify(unknown)}`)
			}
		}
	})

	// rate limit requests that change state by the admin's verified email,
	// prefixed so they never share a key with the client API's IP addresses
	app.use(async (c, next) => {
		const limiter = c.env.RATE_LIMITER
		const email = c.get("email")
		if (limiter === undefined || email === undefined || SafeMethods.has(c.req.method)) {
			return await next()
		}

		const key = `admin:${email}`
		let success: boolean
		try {
			success = (await limiter.limit({ key })).success
		} catch (err) {
			// a failing limiter must not stop admins, as it does not stop the client API
			l.error("rate limiter failed", "error", err)
			return await next()
		}

		if (!success) {
			l.warn("admin request was rate limited", "key", key, "method", c.req.method, "path", c.req.path)
			return c.text("Too Many Requests", 429)
		}

		return await next()
	})

	app.get("/", (c) => c.redirect(certificatesPath("user")))

	app.get("/:kind/certificates", async (c) => {
		const kind = certificateKind(c.req.param("kind"))
		if (kind === undefined) {
			return c.notFound()
		}

		const email = adminEmail(c)
		const query = CertificateListQuery.safeParse(c.req.query())
		if (!query.success) {
			return page(c, <ErrorPage email={email} title="Invalid filters" message={`The filters are not valid: ${query.error.issues.map((i) => `${i.path.join(".")} ${i.message}`).join(", ")}.`} />, 400)
		}

		const { certificates, next } = await listCertificates(env, {
			certificateType: certificateType(kind),
			status: query.data.status,
			principal: query.data.principal,
			keyId: query.data.key_id,
			serial: query.data.serial,
			before: query.data.before,
		})
		const now = new Date()

		return page(c, <CertificateListPage
			email={email}
			kind={kind}
			query={query.data}
			certificates={certificates.map((certificate) => ({ ...certificate, status: certificateStatus(certificate, now) }))}
			nextPage={next === undefined ? undefined : certificatesLink(kind, { ...query.data, before: next })}
		/>)
	})

	app.get("/:kind/certificates/:serial", async (c) => {
		const kind = certificateKind(c.req.param("kind"))
		if (kind === undefined) {
			return c.notFound()
		}

		const email = adminEmail(c)
		const serial = SerialString.safeParse(c.req.param("serial"))
		const certificate = serial.success ? await getCertificate(env, serial.data, certificateType(kind)) : undefined
		if (certificate === undefined) {
			return page(c, <ErrorPage email={email} title="Certificate not found" message={`There is no ${kind} certificate with that serial.`} />, 404)
		}

		return page(c, <CertificateDetailPage email={email} kind={kind} certificate={certificate} status={certificateStatus(certificate)} />)
	})

	app.get(StylesheetPath.slice(AdminBasePath.length), (c) => {
		return c.body(Stylesheet, 200, { "Content-Type": "text/css; charset=utf-8" })
	})

	return app
}
