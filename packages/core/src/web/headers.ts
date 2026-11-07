import type { Env, MiddlewareHandler } from "hono"

/**
 * The headers on every response from the CA's HTML pages (the admin UI and
 * the landing page), including errors and the 404 the admin UI answers with
 * while it is turned off. The landing page has no client-side JavaScript and
 * loads nothing but its own stylesheet. The admin UI adds its own script to
 * the policy, see `AdminSecurityHeaders`.
 *
 * Responses are not cached, except for stylesheets and scripts served as a
 * `HashedAsset`, which set their own `Cache-Control`.
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
 * Sets security headers, by default {@link SecurityHeaders}, on the response
 * to every request it handles, once the rest of the request has been
 * handled. A `Cache-Control` already on the response is kept, as only
 * hashed assets set one, so everything else is sent with the one in the
 * headers.
 *
 * @param headers The headers to set
 * @returns The middleware
 */
export const securityHeaders = <E extends Env>(headers: Readonly<Record<string, string>> = SecurityHeaders): MiddlewareHandler<E> => async (c, next) => {
	await next()

	for (const [name, value] of Object.entries(headers)) {
		if (name === "Cache-Control" && c.res.headers.has(name)) {
			continue
		}

		c.res.headers.set(name, value)
	}
}
