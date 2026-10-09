// Worker entry point used by startWorkerd, bundled by Wrangler when the test
// server starts.
//
// The CA's default export is used as on Cloudflare Workers, wrapped only to
// log each request and to write console output as JSON lines, as the Node.js
// runtime does.
import ca from "@andrewheberle/serverless-ssh-ca"
import { formatArgs, formatRequest } from "./format.js"

type FetchParameters = Parameters<typeof ca.fetch>

// workerd formats objects passed to console for display rather than as JSON,
// so format them here
for (const level of ["debug", "info", "log", "warn", "error"] as const) {
	const write = console[level].bind(console)
	console[level] = (...args: unknown[]): void => write(formatArgs(args))
}

export default {
	...ca,
	async fetch(request: FetchParameters[0], env: FetchParameters[1], ctx: FetchParameters[2]): Promise<Response> {
		const response = await ca.fetch(request, env, ctx)
		const url = new URL(request.url)
		const body = response.status >= 400 ? await response.clone().text() : ""

		console.log(formatRequest(request.method, url.pathname + url.search, response.status, body))

		return response
	},
}
