import { ApiException, InputValidationException } from "chanfana"
import type { Env, MiddlewareHandler } from "hono"
import { bodyLimit } from "hono/body-limit"
import { errorResponse } from "../errors.js"

/**
 * The largest request body the API accepts, in bytes. The largest valid
 * request, a host certificate request with the most principals a certificate
 * can have, is well under this.
 */
export const MaxRequestBodySize = 64 * 1024

/**
 * Thrown for a request whose body is larger than {@link MaxRequestBodySize}.
 */
export class PayloadTooLargeException extends ApiException {
	override isVisible = true
	override default_message = "request body is too large"
	override status = 413
	override code = 413
}

/**
 * Refuses a request whose body is larger than {@link MaxRequestBodySize} with a
 * 413, before anything reads or parses it.
 *
 * @returns The middleware
 */
export const requestBodyLimit = <E extends Env>(): MiddlewareHandler<E> => bodyLimit({
	maxSize: MaxRequestBodySize,
	onError: () => errorResponse(new PayloadTooLargeException()),
})

// the methods whose requests to the API have a JSON body
const BodyMethods = new Set(["POST", "PUT", "PATCH"])

/**
 * Refuses a request with a body that is not valid JSON with a 400, rather than
 * letting chanfana read it as `{}` and report every field as missing. The body
 * is read from a copy of the request, so the route still reads it. An empty
 * body is left to the route, which reports the fields it needs.
 *
 * @returns The middleware
 */
export const requireJsonBody = <E extends Env>(): MiddlewareHandler<E> => async (c, next) => {
	if (BodyMethods.has(c.req.method) && c.req.raw.body !== null) {
		const text = await c.req.raw.clone().text()
		if (text.trim() !== "") {
			try {
				JSON.parse(text)
			} catch {
				throw new InputValidationException("request body is not valid JSON", ["body"])
			}
		}
	}

	await next()
}
