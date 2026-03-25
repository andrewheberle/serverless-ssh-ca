import { Logger } from "@andrewheberle/ts-slog";
import { tryWhile } from "@cloudflare/actors"
import { env } from "cloudflare:workers";

export const runStatement = async (stmt: D1PreparedStatement) => {
  return await tryWhile(async () => {
    return await stmt.run();
  }, shouldRetry);
}

export const shouldRetry = (err: unknown, nextAttempt: number) => {
    const errMsg = String(err);
    const isRetryableError =
        errMsg.includes("Network connection lost") ||
        errMsg.includes("storage caused object to be reset") ||
        errMsg.includes("reset because its code was updated") ||
        errMsg.includes("stream because client disconnected")
    
    if (nextAttempt <= 5 && isRetryableError) {
        return true
    }

    return false
}

export const dbCleanup = async () => {
    const logger = new Logger().with("retention", env.DB_CERTIFICATE_RETENTION)

    // @ts-expect-error: This is flagged but only due to the Workers type generation
    if (env.DB_CERTIFICATE_RETENTION === "infinite") {
        logger.info("skipping database cleanup")
    }

    logger.info("starting database cleanup")
    try {
        const stmt = env.DB.prepare("DELETE FROM certificates WHERE unixepoch('subsec') > unixepoch(valid_before,'subsec',?)")
            .bind(env.DB_CERTIFICATE_RETENTION)
        const res = await stmt.run()
        logger.info("completed database cleanup", "changes", res.meta.changes)
    } catch (err) {
        logger.error("error during database cleanup", "retention", env.DB_CERTIFICATE_RETENTION)
    }
}
