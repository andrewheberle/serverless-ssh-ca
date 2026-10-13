import type { SshCaBindings } from "./types.js"
import { Logger, LogLevel } from "@andrewheberle/ts-slog"

// how many causes of an error are logged, in case a chain of causes loops
const MaxCauseDepth = 5

/**
 * Returns a value to log, with an error converted to a plain object. Errors
 * have no enumerable properties, so are otherwise logged as little more than
 * their name.
 */
const logValue = (value: unknown, depth = 0): unknown => {
	if (!(value instanceof Error)) {
		return value
	}

	return {
		name: value.name,
		message: value.message,
		...(value.cause === undefined || depth >= MaxCauseDepth ? {} : { cause: logValue(value.cause, depth + 1) }),
		stack: value.stack,
	}
}

export const logger = (env: SshCaBindings): Logger => {
	const level = env.LOG_LEVEL === "none"
		? LogLevel.None
		: env.LOG_LEVEL === "error"
			? LogLevel.Error
			: env.LOG_LEVEL === "warning"
				?  LogLevel.Warning
				: env.LOG_LEVEL == "debug"
					? LogLevel.Debug
					: LogLevel.Info
	
	return new Logger({
		minLevel: level,
		logHandler: (output) => console.log(Object.fromEntries(Object.entries(output).map(([key, value]) => [key, logValue(value)]))),
	})
}
