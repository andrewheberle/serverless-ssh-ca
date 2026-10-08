import { readFile } from "node:fs/promises"
import type { CaSecret } from "../types.js"

/**
 * Use a string as the CA's private key secret.
 *
 * @example
 * ```ts
 * const PRIVATE_KEY = secretFromString(process.env.SSH_CA_PRIVATE_KEY ?? "")
 * ```
 *
 * @param value The CA private key in OpenSSH format
 * @returns A secret for the `PRIVATE_KEY` binding, see {@link CaSecret}
 */
export const secretFromString = (value: string): CaSecret => ({
	get: async (): Promise<string> => value,
})

/**
 * Use the contents of a file as the CA's private key secret.
 *
 * The file is read each time the key is needed, so replacing the file takes
 * effect without a restart.
 *
 * @param path The path of a file containing the CA private key in OpenSSH format
 * @returns A secret for the `PRIVATE_KEY` binding, see {@link CaSecret}
 */
export const secretFromFile = (path: string): CaSecret => ({
	get: async (): Promise<string> => await readFile(path, { encoding: "utf-8" }),
})
