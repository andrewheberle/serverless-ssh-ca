import { Logger, LogLevel } from "@andrewheberle/ts-slog"
import { env } from "cloudflare:workers"

export const logger = new Logger({ minLevel: env.LOG_LEVEL as string === "debug" ? LogLevel.Debug : LogLevel.Info })
