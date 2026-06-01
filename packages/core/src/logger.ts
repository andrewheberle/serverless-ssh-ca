import type { SshCaBindings } from "./types"
import { Logger, LogLevel } from "@andrewheberle/ts-slog"

export const logger = (env: SshCaBindings) => (
	new Logger({ minLevel: env.LOG_LEVEL as string === "debug" ? LogLevel.Debug : LogLevel.Info })
)
