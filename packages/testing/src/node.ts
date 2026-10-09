import { createServer, type IncomingMessage } from "node:http"
import { DatabaseSync } from "node:sqlite"
import { createSshCa } from "@andrewheberle/serverless-ssh-ca"
import { bindingsFromEnv, fromNodeSqlite, secretFromString } from "@andrewheberle/serverless-ssh-ca/node"
import type { TestServerConfig } from "./config.js"
import { formatArgs } from "./format.js"
import type { LogFile } from "./log.js"
import type { TestServer } from "./server.js"

const consoleMethods = ["debug", "info", "log", "warn", "error"] as const

// convert a request received by the HTTP server into a Fetch API request
const toRequest = async (req: IncomingMessage): Promise<Request> => {
	const chunks: Buffer[] = []
	for await (const chunk of req) {
		chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(String(chunk)))
	}

	const headers = new Headers()
	for (const [name, values] of Object.entries(req.headersDistinct)) {
		for (const value of values ?? []) {
			headers.append(name, value)
		}
	}

	const method = req.method ?? "GET"

	return new Request(`http://${req.headers.host ?? "localhost"}${req.url ?? "/"}`, {
		method,
		headers,
		body: method === "GET" || method === "HEAD" ? undefined : Buffer.concat(chunks),
	})
}

/**
 * Run the CA on Node.js, created with the package's Node.js helpers and an
 * in-memory `node:sqlite` database, behind an HTTP server on a random port.
 *
 * Output the CA writes with `console` is written to `log` until the server is
 * closed.
 *
 * @param config The test server configuration
 * @param log The log file for the CA and harness
 * @returns The running server
 * @throws InvalidConfigurationError if `config.bindings` is not a valid CA configuration
 */
export const startNode = async (config: TestServerConfig, log: LogFile): Promise<TestServer> => {
	const db = new DatabaseSync(":memory:")

	// bindingsFromEnv validates the configuration so a mistake fails at start up
	const ca = createSshCa(bindingsFromEnv({
		DB: fromNodeSqlite(db),
		PRIVATE_KEY: secretFromString(config.private_key),
	}, config.bindings))

	// the CA logs JSON lines via console, so send them to the log file
	const original = consoleMethods.map(level => [level, console[level]] as const)
	for (const level of consoleMethods) {
		console[level] = (...args: unknown[]): void => log.write(formatArgs(args))
	}
	const restoreConsole = (): void => {
		for (const [level, method] of original) {
			console[level] = method
		}
	}

	const server = createServer(async (req, res) => {
		try {
			const request = await toRequest(req)
			const response = await ca.fetch(request)
			const body = Buffer.from(await response.arrayBuffer())

			log.request(request.method, req.url ?? "/", response.status, body.toString())

			res.writeHead(response.status, Object.fromEntries(response.headers))
			res.end(body)
		} catch (err) {
			log.fault("request failed", err)
			res.writeHead(502)
			res.end()
		}
	})

	try {
		await new Promise<void>((resolve, reject) => {
			server.once("error", reject)
			server.listen(0, "127.0.0.1", () => resolve())
		})
	} catch (err) {
		restoreConsole()
		db.close()
		throw err
	}

	const address = server.address()
	if (address === null || typeof address === "string") {
		restoreConsole()
		server.close()
		db.close()
		throw new Error(`unexpected server address: ${String(address)}`)
	}

	return {
		port: address.port,
		close: async (): Promise<void> => {
			server.closeAllConnections()
			await new Promise<void>(resolve => server.close(() => resolve()))
			restoreConsole()
			db.close()
		},
	}
}
