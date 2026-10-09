import { fileURLToPath } from "node:url"
import { createTestHarness } from "wrangler"
import type { TestServerConfig } from "./config.js"
import type { LogFile } from "./log.js"
import type { TestServer } from "./server.js"

// the Secrets Store binding exposes an admin API in local development, used
// to create the CA private key secret
type SecretsStoreAdmin = {
	create(value: string): Promise<string>
}

type WorkerEnv = {
	PRIVATE_KEY: {
		"SecretsStoreSecret::admin_api": () => Promise<SecretsStoreAdmin>
	}
}

/**
 * The Workers compatibility date the CA is run with, which matches the
 * configuration the CA is tested with on Workers.
 */
export const COMPATIBILITY_DATE = "2026-03-13"

/**
 * Run the CA under workerd, the Cloudflare Workers runtime, using the Wrangler
 * test harness as "wrangler dev" would, with a local D1 database and Secrets
 * Store that are not persisted.
 *
 * The CA's output is copied to `log` every 100ms and when the server is
 * closed. Errors from workerd itself, such as an uncaught exception, are
 * logged as harness faults.
 *
 * @param config The test server configuration
 * @param log The log file for the CA and harness
 * @param root The directory Wrangler's working files are written to
 * @returns The running server
 */
export const startWorkerd = async (config: TestServerConfig, log: LogFile, root: string): Promise<TestServer> => {
	// use placeholder request.cf data rather than downloading it from
	// Cloudflare and caching it in the working directory
	process.env.CLOUDFLARE_CF_FETCH_ENABLED = "false"

	const server = createTestHarness({
		root,
		workers: [{
			config: {
				name: "serverless-ssh-ca",
				main: fileURLToPath(new URL("./worker.js", import.meta.url)),
				compatibility_date: COMPATIBILITY_DATE,
				compatibility_flags: ["nodejs_compat"],
				vars: config.bindings,
				d1_databases: [{
					binding: "DB",
					database_name: "ssh-ca-database",
					database_id: "00000000-0000-0000-0000-000000000000",
				}],
				secrets_store_secrets: [{
					binding: "PRIVATE_KEY",
					store_id: "test",
					secret_name: "ssh-ca-private-key",
				}],
			},
		}],
	})

	// copy the runtime logs to the log file. Errors that are not JSON lines
	// from the CA are from workerd, such as an uncaught exception, so are
	// logged as a harness fault.
	const flushLogs = (): void => {
		for (const entry of server.getLogs()) {
			let json = true
			try {
				JSON.parse(entry.message)
			} catch {
				json = false
			}

			if (json || entry.level !== "error") {
				log.write(entry.message)
			} else {
				log.fault("runtime error", entry.message)
			}
		}
		server.clearLogs()
	}

	try {
		const { url } = await server.listen()

		// the secret must exist before the port is reported and requests are made
		const env = await server.getWorker<WorkerEnv>().getEnv()
		const secrets = await env.PRIVATE_KEY["SecretsStoreSecret::admin_api"]()
		await secrets.create(config.private_key)

		const timer = setInterval(flushLogs, 100)

		return {
			port: Number(url.port),
			close: async (): Promise<void> => {
				clearInterval(timer)
				flushLogs()
				await server.close()
			},
		}
	} catch (err) {
		flushLogs()
		await server.close()
		throw err
	}
}
