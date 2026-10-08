/**
 * Helpers for running the CA on Node.js, imported from
 * `@andrewheberle/serverless-ssh-ca/node`.
 *
 * @example
 * ```ts
 * import { DatabaseSync } from "node:sqlite"
 * import { createSshCa } from "@andrewheberle/serverless-ssh-ca"
 * import { bindingsFromEnv, fromNodeSqlite, secretFromFile } from "@andrewheberle/serverless-ssh-ca/node"
 *
 * const ca = createSshCa(bindingsFromEnv({
 *     DB: fromNodeSqlite(new DatabaseSync("ssh-ca.sqlite")),
 *     PRIVATE_KEY: secretFromFile("/etc/ssh-ca/ca_key"),
 * }))
 * ```
 *
 * @packageDocumentation
 */
export { bindingsFromEnv, EnvSchema, InvalidConfigurationError } from "./env.js"
export type { CaEnv } from "./env.js"
export { secretFromFile, secretFromString } from "./secret.js"
export { fromNodeSqlite } from "./sqlite.js"
