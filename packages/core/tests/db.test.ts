import { describe, it, expect } from "vitest"
import { DatabaseSync } from "node:sqlite"
import { dbCleanup, isRevoked, recordCertificate, recordRenewal, revokeCertificate } from "../src/db/index.js"
import { hostCertificate } from "./helpers/certificate.js"
import { fromNodeSqlite } from "../src/node/index.js"
import { CertificateType } from "../src/db/types.js"
import { makeEnv } from "./env.js"
import { MockSecretStore } from "./helpers/secret.js"
import { key as ecdsaKey } from "./keys/ecdsa.js"
import { key as ed25519Key } from "./keys/ed25519.js"
import { PublicKey } from "../src/ssh/keys.js"
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
		const issue = async () => hostCertificate(ecdsaKey.ca(), ecdsaKey.host())
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
		await revokeCertificate(env, { serial: previous.serial, certificateType: CertificateType.Host, revoker: { kind: "keyHolder", publicKey: previous.publicKey } })
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

describe("revokeCertificate", () => {
	const setup = async () => {
		const sqlite = new DatabaseSync(":memory:")
		const env = makeEnv({ DB: fromNodeSqlite(sqlite), PRIVATE_KEY: new MockSecretStore(ecdsaKey.ca().privateKey) })
		const certificate = hostCertificate(ecdsaKey.ca(), ecdsaKey.host())
		await recordCertificate(env, certificate, certificate.keyId, CertificateType.Host)

		const revokedAt = (): unknown => sqlite.prepare("SELECT revoked_at FROM certificates WHERE serial = ?").get(`${certificate.serial}`)
		const revision = (): unknown => sqlite.prepare("SELECT revision FROM krl WHERE certificate_type = ?").get(CertificateType.Host)

		return { env, certificate, revokedAt, revision }
	}

	it("should only revoke a certificate once, keeping the first revocation time", async () => {
		const { env, certificate, revokedAt } = await setup()
		const revocation = { serial: certificate.serial, certificateType: CertificateType.Host, revoker: { kind: "keyHolder", publicKey: certificate.publicKey } } as const

		const first = await revokeCertificate(env, revocation)
		if (first.kind !== "revoked") {
			throw new Error(`expected the certificate to be revoked, not ${first.kind}`)
		}

		// a second revocation, as from a request that lost a race, changes nothing
		expect(await revokeCertificate(env, revocation)).toEqual({ kind: "alreadyRevoked" })
		expect(revokedAt()).toEqual({ revoked_at: first.revokedAt })
	})

	it("should not revoke a certificate of another type", async () => {
		const { env, certificate, revokedAt, revision } = await setup()

		const result = await revokeCertificate(env, { serial: certificate.serial, certificateType: CertificateType.User, revoker: { kind: "keyHolder", publicKey: certificate.publicKey } })

		expect(result).toEqual({ kind: "notFound" })
		expect(revokedAt()).toEqual({ revoked_at: null })
		expect(revision()).toEqual({ revision: 0 })
	})

	it("should not revoke a certificate for another key", async () => {
		const { env, certificate, revokedAt, revision } = await setup()
		const other = PublicKey.parse(ed25519Key.host().publicKey)

		const result = await revokeCertificate(env, { serial: certificate.serial, certificateType: CertificateType.Host, revoker: { kind: "keyHolder", publicKey: other } })

		expect(result).toEqual({ kind: "notFound" })
		expect(revokedAt()).toEqual({ revoked_at: null })
		expect(revision()).toEqual({ revision: 0 })
	})

	it("should report a serial that is not recorded as not found", async () => {
		const { env, certificate } = await setup()

		expect(await revokeCertificate(env, { serial: certificate.serial + 1n, certificateType: CertificateType.Host, revoker: { kind: "keyHolder", publicKey: certificate.publicKey } }))
			.toEqual({ kind: "notFound" })
	})
})
