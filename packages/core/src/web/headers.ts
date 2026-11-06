import type { Env, MiddlewareHandler } from "hono"

/**
 * The headers on every response from the CA's HTML pages (the admin UI and
 * the landing page), including errors and the 404 the admin UI answers with
 * while it is turned off. The pages have no client-side JavaScript and load
 * nothing but their own stylesheet.
 */
export const SecurityHeaders: Readonly<Record<string, string>> = {
	"Content-Security-Policy": "default-src 'none'; style-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'",
	"Cache-Control": "no-store",
	// no other site is sent a referrer. no-referrer would also make browsers
	// send "Origin: null" on the admin UI's own form posts, which the check
	// against cross-site requests would then refuse
	"Referrer-Policy": "same-origin",
	"X-Content-Type-Options": "nosniff",
}

/**
 * Sets {@link SecurityHeaders} on the response to every request it handles,
 * once the rest of the request has been handled.
 *
 * @returns The middleware
 */
export const securityHeaders = <E extends Env>(): MiddlewareHandler<E> => async (c, next) => {
	await next()

	for (const [name, value] of Object.entries(SecurityHeaders)) {
		c.res.headers.set(name, value)
	}
}
