import { tryWhile } from "@cloudflare/actors"

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
