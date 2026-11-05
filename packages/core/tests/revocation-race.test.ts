import { describe, it, expect } from "vitest"
import { DatabaseSync } from "node:sqlite"
import { getKrlRevision, recordCertificate, revokeCertificate, type RevocationResult } from "../src/db/index.js"
import { CertificateType } from "../src/db/types.js"
import { fromNodeSqlite } from "../src/node/index.js"
import type { CaDatabase } from "../src/types.js"
import { makeEnv } from "./env.js"
import { hostCertificate } from "./helpers/certificate.js"
import { MockSecretStore } from "./helpers/secret.js"
import { key as ecdsaKey } from "./keys/ecdsa.js"

// a database whose batches wait until a number of them have been started, so
// every revocation reads the certificate before any of them revokes it
const withBatchBarrier = (db: CaDatabase, count: number): CaDatabase => {
	let waiting = 0
	let release: () => void = () => undefined
	const barrier = new Promise<void>((resolve) => { release = resolve })

	return {
		prepare: (query) => db.prepare(query),
		exec: async (query) => await db.exec(query),
		batch: async (statements) => {
			waiting++
			if (waiting === count) {
				release()
			}
			await barrier

			return await db.batch(statements)
		},
	}
}

describe("revoking a certificate concurrently", () => {
	it("should revoke it once, keeping the first revocation time", async () => {
		const requests = 5
		const sqlite = new DatabaseSync(":memory:")
		const env = makeEnv({ DB: fromNodeSqlite(sqlite), PRIVATE_KEY: new MockSecretStore(ecdsaKey.ca().privateKey) })
		const certificate = hostCertificate(ecdsaKey.ca(), ecdsaKey.host())
		await recordCertificate(env, certificate, certificate.keyId, CertificateType.Host)
		expect(await getKrlRevision(env, CertificateType.Host)).toBe(0n)

		const racing = { ...env, DB: withBatchBarrier(env.DB, requests) }
		const results = await Promise.all(Array.from({ length: requests }, async (): Promise<RevocationResult> => await revokeCertificate(racing, {
			serial: certificate.serial,
			certificateType: CertificateType.Host,
			revoker: { kind: "keyHolder", publicKey: certificate.publicKey },
		})))

		const revoked = results.filter((result) => result.kind === "revoked")
		expect(revoked).toHaveLength(1)
		expect(results.filter((result) => result.kind === "alreadyRevoked")).toHaveLength(requests - 1)

		expect(sqlite.prepare("SELECT revoked_at FROM certificates WHERE serial = ?").get(`${certificate.serial}`)).toEqual({ revoked_at: revoked[0]?.revokedAt })
		expect(await getKrlRevision(env, CertificateType.Host)).toBe(1n)
	})
})
