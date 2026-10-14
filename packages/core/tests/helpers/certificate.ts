import { randomBytes } from "node:crypto"
import { SshCertificate } from "../../src/ssh/certificate.js"
import type { CaDatabase, CaPreparedStatement } from "../../src/types.js"
import type { TestKey } from "../keys/types.js"
import { signCertificate } from "./ssh-keygen.js"

/**
 * Returns a host certificate signed by a CA key with ssh-keygen, with a random
 * serial, for tests that need a certificate without issuing one.
 */
export const hostCertificate = (ca: TestKey, key: TestKey, options: { principals?: string[], validity?: string, serial?: bigint } = {}): SshCertificate => {
	const principals = options.principals ?? ["test_host"]

	return SshCertificate.parse(signCertificate(ca, key.publicKey, {
		kind: "host",
		keyId: `host_${principals[0]}`,
		principals,
		serial: options.serial ?? randomBytes(8).readBigUInt64BE(),
		validity: options.validity ?? "-1m:+30d",
	}))
}

/**
 * Wraps a database so that any statement that records a certificate fails,
 * while migrations and reads still work, as when a database becomes
 * unavailable part way through a request.
 */
export const failingCertificateWrites = (db: CaDatabase): CaDatabase => {
	const originals = new Map<CaPreparedStatement, CaPreparedStatement>()

	const wrap = (statement: CaPreparedStatement, fails: boolean): CaPreparedStatement => {
		const wrapped: CaPreparedStatement = {
			bind: (...values) => wrap(statement.bind(...values), fails),
			all: async () => fails ? Promise.reject(new Error("database unavailable")) : await statement.all(),
			run: async () => fails ? Promise.reject(new Error("database unavailable")) : await statement.run(),
		}
		originals.set(wrapped, statement)
		if (fails) {
			failing.add(wrapped)
		}
		return wrapped
	}
	const failing = new Set<CaPreparedStatement>()

	return {
		prepare: (query) => wrap(db.prepare(query), /^\s*INSERT\s+INTO\s+"?certificates"?/i.test(query)),
		batch: async (statements) => {
			if (statements.some((statement) => failing.has(statement))) {
				throw new Error("database unavailable")
			}
			return await db.batch(statements.map((statement) => originals.get(statement) ?? statement))
		},
		exec: async (query) => await db.exec(query),
	}
}

/**
 * A database for which every use fails.
 */
export const unavailableDatabase = (): CaDatabase => ({
	prepare: () => {
		throw new Error("database unavailable")
	},
	batch: async () => {
		throw new Error("database unavailable")
	},
	exec: async () => {
		throw new Error("database unavailable")
	},
})
