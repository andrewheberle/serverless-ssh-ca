/**
 * Runs the Serverless SSH CA for end-to-end tests of clients, under Node.js or
 * workerd, configured from a file and reporting what it does through a log
 * file of JSON lines (see {@link LogFile}).
 *
 * Most clients run the `serverless-ssh-ca-test-server` command rather than
 * using this module directly.
 *
 * @example
 * ```ts
 * import { startTestServer } from "@andrewheberle/serverless-ssh-ca-testing"
 *
 * const server = await startTestServer("node", "config.json")
 * // make requests to http://127.0.0.1:${server.port}
 * await server.close()
 * ```
 *
 * @packageDocumentation
 */
import { writeFile } from "node:fs/promises"
import { dirname, resolve } from "node:path"
import { readConfig, type Runtime } from "./config.js"
import { LogFile } from "./log.js"
import { startNode } from "./node.js"
import type { TestServer } from "./server.js"

export { ConfigSchema, readConfig, RuntimeSchema } from "./config.js"
export type { Runtime, TestServerConfig } from "./config.js"
export { FAULT_MESSAGE, FAULT_MESSAGES, isFault, LogFile } from "./log.js"
export type { TestServer } from "./server.js"

/**
 * Start the CA under `runtime` using the configuration in `configFile` (see
 * {@link ConfigSchema}), then write the port it is listening on to the
 * configuration's `port_file`.
 *
 * Output from the CA and harness is appended to the configuration's
 * `log_file`, see {@link LogFile}. Under workerd, Wrangler's working files are
 * written to the directory containing `configFile`.
 *
 * @param runtime The runtime to run the CA under, see {@link Runtime}
 * @param configFile The path of the configuration file
 * @returns The running server, see {@link TestServer}
 */
export const startTestServer = async (runtime: Runtime, configFile: string): Promise<TestServer> => {
	const config = await readConfig(configFile)
	const log = new LogFile(config.log_file)

	let server: TestServer
	switch (runtime) {
		case "node":
			server = await startNode(config, log)
			break
		case "workerd": {
			// loaded on demand as importing Wrangler is slow
			const { startWorkerd } = await import("./workerd.js")
			server = await startWorkerd(config, log, dirname(resolve(configFile)))
			break
		}
		default: {
			const unknown: never = runtime
			throw new Error(`unknown runtime: ${String(unknown)}`)
		}
	}

	try {
		await writeFile(config.port_file, String(server.port))
	} catch (err) {
		await server.close()
		throw err
	}

	return server
}
