import { appendFileSync } from "node:fs"
import z from "zod"
import { formatRequest, formatValue } from "./format.js"

/**
 * Messages the CA logs at error level when it has failed rather than rejected
 * a request, see {@link isFault}.
 */
export const FAULT_MESSAGES: readonly string[] = ["unhandled error", "unexpected error from router"]

/**
 * The message of the line written by {@link LogFile.write} after a CA log line
 * that indicates a fault.
 */
export const FAULT_MESSAGE = "harness fault"

// the fields of a CA log line used to detect faults
const LogLineSchema = z.object({
	level: z.string(),
	message: z.string(),
})

/**
 * Report whether a line logged by the CA indicates a fault, such as a database
 * error, rather than an expected rejection of a request. Some faults are only
 * logged, as the CA still issues a certificate when it cannot record it.
 *
 * @param line A line of output from the CA
 * @returns true if the line is an error logged by the CA for a fault
 */
export const isFault = (line: string): boolean => {
	let json: unknown
	try {
		json = JSON.parse(line)
	} catch {
		return false
	}

	const result = LogLineSchema.safeParse(json)
	if (!result.success || result.data.level.toLowerCase() !== "error") {
		return false
	}

	return FAULT_MESSAGES.includes(result.data.message) || result.data.message.includes("database")
}

/**
 * The log file of a test server, written as JSON lines.
 *
 * Lines from the CA are written as they are logged. The harness adds the
 * following lines, whose messages all start with "harness":
 *
 * - `{"level":"info","message":"harness request",...}` for each request, with
 *   `method`, `url`, `status` and, when `status` is 400 or more, the response
 *   `body`.
 * - `{"level":"error","message":"harness ...",...}` for a fault in the CA or
 *   harness. A CA log line that indicates a fault (see {@link isFault}) is
 *   followed by a line with the message {@link FAULT_MESSAGE}.
 */
export class LogFile {
	readonly path: string

	constructor(path: string) {
		this.path = path
	}

	/**
	 * Append a line of output from the CA, followed by a fault line if it
	 * indicates a fault.
	 */
	write(line: string): void {
		this.append(line)
		if (isFault(line)) {
			this.append(formatValue({ level: "error", message: FAULT_MESSAGE, line }))
		}
	}

	/**
	 * Append a request handled by the CA.
	 */
	request(method: string, url: string, status: number, body: string): void {
		this.append(formatRequest(method, url, status, body))
	}

	/**
	 * Append a fault in the harness.
	 *
	 * @param message A description of the fault, which is prefixed with "harness"
	 * @param error The error that caused the fault
	 */
	fault(message: string, error: unknown): void {
		this.append(formatValue({ level: "error", message: `harness ${message}`, error }))
	}

	private append(line: string): void {
		appendFileSync(this.path, line + "\n")
	}
}
