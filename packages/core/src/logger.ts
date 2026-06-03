import type { SshCaBindings } from "./types"
import { Logger, LogLevel } from "@andrewheberle/ts-slog"

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
	
	return new Logger({ minLevel: level })
}
