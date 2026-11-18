import type { Env, MiddlewareHandler } from "hono"
import { SecurityHeaders } from "./headers.js"

/**
 * Where the API docs page (Swagger UI, served by chanfana) loads its scripts
 * and stylesheet from. chanfana pins them with subresource integrity.
 */
export const DocsAssetOrigin = "https://cdn.jsdelivr.net"

// the scripts of a page, matched as browsers do: tag names in any case, and a
// closing tag that may have whitespace or attributes before its ">"
const Script = /<script\b([^>]*)>([\s\S]*?)<\/script\b[^>]*>/gi

/**
 * Returns the CSP hash sources (`'sha256-...'`) of the inline scripts of an
 * HTML page, so a policy can allow exactly those scripts.
 *
 * @param html The page
 * @returns The hash source of each inline script
 */
export const inlineScriptHashes = async (html: string): Promise<string[]> => {
	const hashes: string[] = []
	for (const [, attributes = "", body = ""] of html.matchAll(Script)) {
		// a script loaded from a URL is allowed by its origin, not its content
		if (body === "" || /\bsrc\s*=/i.test(attributes)) {
			continue
		}

		const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(body)))
		hashes.push(`'sha256-${btoa(String.fromCharCode(...digest))}'`)
	}

	return hashes
}

/**
 * Returns the Content-Security-Policy of the API docs page, which allows
 * Swagger UI's scripts and stylesheet from {@link DocsAssetOrigin}, the page's
 * own inline scripts by hash, and fetching the schema from the CA itself.
 *
 * @param scriptHashes The hash sources of the page's inline scripts, see {@link inlineScriptHashes}
 * @returns The policy
 */
export const docsContentSecurityPolicy = (scriptHashes: string[]): string => [
	"default-src 'none'",
	`script-src ${[DocsAssetOrigin, ...scriptHashes].join(" ")}`,
	`style-src ${DocsAssetOrigin}`,
	"img-src 'self' data:",
	"connect-src 'self'",
	"form-action 'none'",
	"frame-ancestors 'none'",
	"base-uri 'none'",
].join("; ")

/**
 * Sets the CA's security headers (see {@link SecurityHeaders}) on the API docs
 * page, with a Content-Security-Policy for Swagger UI (see
 * {@link docsContentSecurityPolicy}) whose script hashes are taken from the
 * page as served, so they stay right when chanfana changes the page.
 *
 * @returns The middleware
 */
export const docsSecurityHeaders = <E extends Env>(): MiddlewareHandler<E> => async (c, next) => {
	await next()

	const hashes = c.res.ok && (c.res.headers.get("Content-Type") ?? "").startsWith("text/html")
		? await inlineScriptHashes(await c.res.clone().text())
		: []

	for (const [name, value] of Object.entries(SecurityHeaders)) {
		c.res.headers.set(name, name === "Content-Security-Policy" ? docsContentSecurityPolicy(hashes) : value)
	}
}

/**
 * Sets `X-Content-Type-Options: nosniff` on the response, for the OpenAPI
 * schema served as JSON.
 *
 * @returns The middleware
 */
export const noSniff = <E extends Env>(): MiddlewareHandler<E> => async (c, next) => {
	await next()
	c.res.headers.set("X-Content-Type-Options", "nosniff")
}
