import type { CaCache } from "../types.js"

type Entry = {
	value: string
	/** When the entry expires in milliseconds since the Unix epoch, if it does */
	expires: number | undefined
}

/**
 * Create an in-memory cache for the `CACHE` binding, with the same shape as a
 * Cloudflare Workers KV namespace (see {@link CaCache}).
 *
 * Entries are kept in memory by the process, so they are lost on restart and
 * not shared between processes.
 *
 * @example
 * ```ts
 * const env = bindingsFromEnv({
 *     DB: fromNodeSqlite(new DatabaseSync("ssh-ca.sqlite")),
 *     PRIVATE_KEY: secretFromFile("/etc/ssh-ca/ca_key"),
 *     CACHE: cacheInMemory(),
 * })
 * ```
 *
 * @returns A cache for the `CACHE` binding, see {@link CaCache}
 */
export const cacheInMemory = (): CaCache => {
	const entries = new Map<string, Entry>()

	const expired = (entry: Entry, now: number): boolean => entry.expires !== undefined && now >= entry.expires

	return {
		get: async (key: string): Promise<string | null> => {
			const entry = entries.get(key)
			if (entry === undefined) {
				return null
			}

			if (expired(entry, Date.now())) {
				entries.delete(key)
				return null
			}

			return entry.value
		},
		put: async (key: string, value: string, options?: { expirationTtl?: number }): Promise<void> => {
			const now = Date.now()

			// remove entries that have expired, as they are not read again
			for (const [k, entry] of entries) {
				if (expired(entry, now)) {
					entries.delete(k)
				}
			}

			entries.set(key, {
				value,
				expires: options?.expirationTtl === undefined ? undefined : now + options.expirationTtl * 1000,
			})
		},
	}
}
