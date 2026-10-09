import { readFile } from "node:fs/promises"
import z from "zod"

/**
 * The runtimes the CA can be run under by {@link startTestServer}: `node` uses
 * the package's Node.js helpers with an in-memory `node:sqlite` database, and
 * `workerd` uses the Cloudflare Workers runtime with a local D1 database and
 * Secrets Store.
 */
export const RuntimeSchema = z.enum(["node", "workerd"])

/**
 * A runtime the CA can be run under, see {@link RuntimeSchema}.
 */
export type Runtime = z.infer<typeof RuntimeSchema>

/**
 * The configuration file read by {@link readConfig}.
 */
export const ConfigSchema = z.object({
	/** The CA private key in OpenSSH format */
	private_key: z.string().min(1),
	/** The CA configuration, as the Workers vars (environment variables) */
	bindings: z.record(z.string(), z.string()),
	/** Path the listening port is written to once the CA is ready */
	port_file: z.string().min(1),
	/** Path that log output from the CA and harness is appended to */
	log_file: z.string().min(1),
})

/**
 * The configuration of a test server, see {@link ConfigSchema}.
 */
export type TestServerConfig = z.infer<typeof ConfigSchema>

/**
 * Read and validate a test server configuration file.
 *
 * @param path The path of a JSON file matching {@link ConfigSchema}
 * @returns The validated configuration
 * @throws Error if the file cannot be read, is not JSON or is not a valid configuration
 */
export const readConfig = async (path: string): Promise<TestServerConfig> => {
	const text = await readFile(path, { encoding: "utf-8" })

	let json: unknown
	try {
		json = JSON.parse(text)
	} catch (err) {
		throw new Error(`parsing ${path}: ${err instanceof Error ? err.message : String(err)}`, { cause: err })
	}

	const result = ConfigSchema.safeParse(json)
	if (!result.success) {
		throw new Error(`invalid configuration in ${path}:\n${z.prettifyError(result.error)}`)
	}

	return result.data
}
