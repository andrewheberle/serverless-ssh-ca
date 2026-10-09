/**
 * Format a value logged by the CA as text, with objects as JSON so log lines
 * from the CA's logger are written as JSON lines.
 *
 * @param value A value passed to a `console` method
 * @returns The value as a string
 */
export const formatValue = (value: unknown): string => typeof value === "string"
	? value
	: JSON.stringify(value, (_, x: unknown) => x instanceof Error
		? { name: x.name, message: x.message, stack: x.stack }
		: typeof x === "bigint" ? x.toString() : x)

/**
 * Format the arguments to a `console` method as a single line.
 *
 * @param args The arguments passed to a `console` method
 * @returns The arguments formatted with {@link formatValue}, separated by spaces
 */
export const formatArgs = (args: readonly unknown[]): string => args.map(formatValue).join(" ")

/**
 * Format a request handled by the CA as a log line, including the response
 * body when the request was rejected.
 *
 * @param method The request method
 * @param url The path and query of the request
 * @param status The response status code
 * @param body The response body
 * @returns A JSON line with the message "harness request"
 */
export const formatRequest = (method: string, url: string, status: number, body: string): string =>
	formatValue({ level: "info", message: "harness request", method, url, status, ...(status >= 400 ? { body } : {}) })
