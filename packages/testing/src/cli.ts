#!/usr/bin/env node
// Runs the Serverless SSH CA for end-to-end tests of clients.
//
// Usage: serverless-ssh-ca-test-server [--runtime node|workerd] <config.json>
//
// The process exits when its stdin is closed, so it does not outlive the test
// that started it.
import { parseArgs } from "node:util"
import z from "zod"
import { readConfig, RuntimeSchema } from "./config.js"
import { startTestServer } from "./index.js"
import { LogFile } from "./log.js"

const usage = "usage: serverless-ssh-ca-test-server [--runtime node|workerd] <config.json>"

const main = async (): Promise<void> => {
	const { values, positionals } = parseArgs({
		options: {
			runtime: { type: "string", default: "node" },
		},
		allowPositionals: true,
	})

	const runtime = RuntimeSchema.safeParse(values.runtime)
	if (!runtime.success) {
		throw new Error(`--runtime ${z.prettifyError(runtime.error)}\n${usage}`)
	}

	const [configFile, ...extra] = positionals
	if (configFile === undefined || extra.length > 0) {
		throw new Error(usage)
	}

	// faults after start up are written to the log file, where the test
	// reading it will find them
	const config = await readConfig(configFile)
	const log = new LogFile(config.log_file)
	process.on("uncaughtException", (err) => {
		log.fault("uncaught exception", err)
		process.exit(1)
	})

	const server = await startTestServer(runtime.data, configFile)

	process.stdin.on("end", () => {
		server.close().then(() => process.exit(0), (err: unknown) => {
			log.fault("close failed", err)
			process.exit(1)
		})
	})
	process.stdin.resume()
}

main().catch((err: unknown) => {
	console.error(err instanceof Error ? err.message : err)
	process.exit(1)
})
