import { describe, it, expect } from "vitest"
import { DatabaseSync } from "node:sqlite"
import { dbCleanup, isRevoked, recordCertificate, recordRenewal, revokeCertificate } from "../src/db/index.js"
import { createSignedHostCertificate } from "../src/certificate.js"
import { fromNodeSqlite } from "../src/node/index.js"
import { CertificateType } from "../src/db/types.js"
import { makeEnv } from "./env.js"
import { MockSecretStore } from "./helpers/secret.js"
import { pub } from "./helpers/keys.js"
import { key as ecdsaKey } from "./keys/ecdsa.js"
import type { CaDatabase } from "../src/types.js"

// a D1 binding that records any use of it
const trackedDatabase = (): { db: CaDatabase, used: PropertyKey[] } => {
	const used: PropertyKey[] = []
	const db = new Proxy({}, {
		get(_, prop) {
			used.push(prop)
			throw new Error("database should not be used")
		},
	}) as unknown as CaDatabase
	return { db, used }
}

describe("dbCleanup", () => {
	it("should not touch the database when retention is infinite", async () => {
		const { db, used } = trackedDatabase()

		await dbCleanup(makeEnv({ DB: db, DB_CERTIFICATE_RETENTION: "infinite" }))

		expect(used).toEqual([])
	})

	it("should use the database when retention is limited", async () => {
		const { db, used } = trackedDatabase()

		await dbCleanup(makeEnv({ DB: db, DB_CERTIFICATE_RETENTION: "1 year" }))

		expect(used).not.toEqual([])
	})
})

describe("recordRenewal", () => {
	const setup = () => {
		const sqlite = new DatabaseSync(":memory:")
		const env = makeEnv({ DB: fromNodeSqlite(sqlite), PRIVATE_KEY: new MockSecretStore(ecdsaKey.ca().privateKey) })
		const issue = async () => await createSignedHostCertificate(env, pub(ecdsaKey.host()), { principals: ["test_host"] })
		const recorded = (serial: bigint) => sqlite.prepare("SELECT revoked_at FROM certificates WHERE serial = ?").get(`${serial}`)
		return { env, issue, recorded }
	}

	it("should record the renewed certificate and revoke the previous one", async () => {
		const { env, issue, recorded } = setup()
		const previous = await issue()
		await recordCertificate(env, previous, previous.keyId, CertificateType.Host)
		const renewed = await issue()

		expect(await recordRenewal(env, previous, renewed)).toBe(true)

		expect(await isRevoked(env, previous.serial)).toBe(true)
		expect(recorded(renewed.serial)).toEqual({ revoked_at: null })
	})

	it("should not record the renewed certificate when the previous one is already revoked", async () => {
		const { env, issue, recorded } = setup()
		const previous = await issue()
		await recordCertificate(env, previous, previous.keyId, CertificateType.Host)
		await revokeCertificate(env, previous.serial)
		const renewed = await issue()

		expect(await recordRenewal(env, previous, renewed)).toBe(false)

		expect(recorded(renewed.serial)).toBeUndefined()
	})

	it("should only record one of two renewals of the same certificate", async () => {
		const { env, issue, recorded } = setup()
		const previous = await issue()
		await recordCertificate(env, previous, previous.keyId, CertificateType.Host)
		const first = await issue()
		const second = await issue()

		const results = await Promise.all([recordRenewal(env, previous, first), recordRenewal(env, previous, second)])

		expect(results.filter((r) => r)).toHaveLength(1)
		expect([recorded(first.serial), recorded(second.serial)].filter((r) => r !== undefined)).toHaveLength(1)
	})

	it("should record and revoke a previous certificate that was not recorded", async () => {
		const { env, issue, recorded } = setup()
		const previous = await issue()
		const renewed = await issue()

		expect(await recordRenewal(env, previous, renewed)).toBe(true)

		expect(await isRevoked(env, previous.serial)).toBe(true)
		expect(recorded(renewed.serial)).toEqual({ revoked_at: null })
	})
})
