import { afterEach, beforeEach, describe, expect, it, vi } from "vitest"
import { DatabaseSync } from "node:sqlite"
import { z } from "zod"
import { createSshCa, type SshCa } from "../src/index.js"
import { recordRenewal } from "../src/db/index.js"
import { applyMigrations } from "../src/db/migrate.js"
import { migrations } from "../src/db/migrations/index.js"
import { fromNodeSqlite, secretFromString } from "../src/node/index.js"
import { SshCertificate } from "../src/ssh/certificate.js"
import { makeEnv } from "./env.js"
import { hostCertificate } from "./helpers/certificate.js"
import { generateProof, generateRequestProof } from "./helpers/proof.js"
import { isRevoked } from "./helpers/ssh-keygen.js"
import { getAccessToken, getIdentityToken } from "./helpers/token.js"
import { key as ecdsaKey } from "./keys/ecdsa.js"
import { key as ed25519Key } from "./keys/ed25519.js"
import type { TestKey } from "./keys/types.js"

const email = "user@example.com"
const claims = { sub: "user123", email }

const CertificateResponse = z.object({ certificate: z.string() })
const KrlResponse = z.object({ krl: z.string() })
const AuditRow = z.object({ requested_by: z.string().nullable(), revoked_by: z.string().nullable(), revocation_reason: z.string().nullable() })
const RenewalRow = z.object({ renewal_of: z.string().nullable() })

const base64 = (value: string): string => Buffer.from(value).toString("base64")

const post = async (ca: SshCa, path: string, body: unknown, headers: Record<string, string> = {}): Promise<Response> => {
	return await ca.fetch(new Request(`http://example.com${path}`, {
		method: "POST",
		headers: { "Content-Type": "application/json", ...headers },
		body: JSON.stringify(body),
	}))
}

// the certificate in a successful response, as text and parsed
const certificateOf = async (response: Response): Promise<{ text: string, certificate: SshCertificate }> => {
	expect(response.status).toBe(200)
	const text = Buffer.from(CertificateResponse.parse(await response.json()).certificate, "base64").toString()
	return { text, certificate: SshCertificate.parse(text) }
}

describe("certificate audit trail", () => {
	let sqlite: DatabaseSync
	let ca: SshCa

	const audit = (serial: bigint): z.infer<typeof AuditRow> => AuditRow.parse(
		sqlite.prepare("SELECT requested_by, revoked_by, revocation_reason FROM certificates WHERE serial = ?").get(`${serial}`),
	)

	const renewalOf = (serial: bigint): string | null => RenewalRow.parse(
		sqlite.prepare("SELECT renewal_of FROM certificates WHERE serial = ?").get(`${serial}`),
	).renewal_of

	const issueUserV4 = async (key: TestKey): Promise<Response> => await post(ca, "/api/v4/user/certificates", {
		public_key: base64(key.publicKey),
		identity: await getIdentityToken(claims),
	}, {
		"Authorization": await getAccessToken(claims),
		"Proof-Of-Possession": generateRequestProof(key, "POST", "/api/v4/user/certificates"),
	})

	const issueHostV4 = async (key: TestKey, principals: string[]): Promise<Response> => await post(ca, "/api/v4/host/certificates", {
		public_key: base64(key.publicKey),
		identity: await getIdentityToken(claims),
		principals,
	}, {
		"Authorization": await getAccessToken(claims),
		"Proof-Of-Possession": generateRequestProof(key, "POST", "/api/v4/host/certificates"),
	})

	const issueHostV3 = async (key: TestKey, principals: string[]): Promise<Response> => await post(ca, "/api/v3/host/certificate", {
		public_key: base64(key.publicKey),
		proof: generateProof(key),
		identity: await getIdentityToken(claims),
		principals,
	}, { "Authorization": await getAccessToken(claims) })

	const renewV4 = async (issued: { text: string, certificate: SshCertificate }, key: TestKey): Promise<Response> => {
		const path = `/api/v4/host/certificates/${issued.certificate.serial}/renew`
		return await post(ca, path, { certificate: base64(issued.text) }, { "Proof-Of-Possession": generateRequestProof(key, "POST", path) })
	}

	beforeEach(() => {
		sqlite = new DatabaseSync(":memory:")
		ca = createSshCa(makeEnv({
			DB: fromNodeSqlite(sqlite),
			PRIVATE_KEY: secretFromString(ed25519Key.ca().privateKey),
			SSH_HOST_CERTIFICATE_ALLOWED_EMAILS: email,
		}))
	})

	afterEach(() => {
		vi.restoreAllMocks()
		sqlite.close()
	})

	describe("issuance", () => {
		it("should record who requested a user certificate", async () => {
			const { certificate } = await certificateOf(await issueUserV4(ecdsaKey.user()))

			expect(audit(certificate.serial)).toEqual({ requested_by: email, revoked_by: null, revocation_reason: null })
		})

		it.each([
			["v3", issueHostV3],
			["v4", (key: TestKey, principals: string[]) => issueHostV4(key, principals)],
		])("should record who requested a host certificate (%s)", async (_version, issue) => {
			const { certificate } = await certificateOf(await issue(ecdsaKey.host(), ["audit.example.com"]))

			expect(audit(certificate.serial)).toEqual({ requested_by: email, revoked_by: null, revocation_reason: null })
		})
	})

	describe("revocation by the key holder", () => {
		it("should record the key holder as the revoker (v3)", async () => {
			const key = ecdsaKey.user()
			const { certificate } = await certificateOf(await issueUserV4(key))

			const response = await post(ca, "/api/v3/user/revoke", { serial: `${certificate.serial}`, public_key: base64(key.publicKey), proof: generateProof(key) })
			expect(response.status).toBe(200)

			expect(audit(certificate.serial)).toEqual({ requested_by: email, revoked_by: "key-holder", revocation_reason: null })
		})

		it("should record the key holder as the revoker (v4)", async () => {
			const key = ecdsaKey.user()
			const { certificate } = await certificateOf(await issueUserV4(key))

			const path = `/api/v4/user/certificates/${certificate.serial}`
			const response = await ca.fetch(new Request(`http://example.com${path}`, {
				method: "DELETE",
				headers: { "Proof-Of-Possession": generateRequestProof(key, "DELETE", path) },
			}))
			expect(response.status).toBe(200)

			expect(audit(certificate.serial)).toEqual({ requested_by: email, revoked_by: "key-holder", revocation_reason: null })
		})

		it("should log the revocation", async () => {
			const key = ecdsaKey.user()
			const { certificate } = await certificateOf(await issueUserV4(key))
			const log = vi.spyOn(console, "log").mockImplementation(() => undefined)
			ca = createSshCa(makeEnv({ DB: fromNodeSqlite(sqlite), PRIVATE_KEY: secretFromString(ed25519Key.ca().privateKey), LOG_LEVEL: "info" }))

			const response = await post(ca, "/api/v3/user/revoke", { serial: `${certificate.serial}`, public_key: base64(key.publicKey), proof: generateProof(key) })
			expect(response.status).toBe(200)

			expect(log).toHaveBeenCalledWith(expect.objectContaining({
				level: "info",
				message: "certificate revoked",
				serial: `${certificate.serial}`,
				certificate_type: "user",
				revoked_by: "key-holder",
				revocation_reason: null,
			}))
		})
	})

	describe("renewal", () => {
		it("should record what a renewal renewed instead of a requester, and the renewed certificate as revoked for renewal", async () => {
			const key = ecdsaKey.host()
			const issued = await certificateOf(await issueHostV4(key, ["renew.example.com"]))

			const renewed = await certificateOf(await renewV4(issued, key))

			expect(audit(issued.certificate.serial)).toEqual({ requested_by: email, revoked_by: "key-holder", revocation_reason: "renewal" })
			expect(renewalOf(issued.certificate.serial)).toBeNull()
			expect(audit(renewed.certificate.serial)).toEqual({ requested_by: null, revoked_by: null, revocation_reason: null })
			expect(renewalOf(renewed.certificate.serial)).toBe(`${issued.certificate.serial}`)
		})

		it("should record each renewal in a chain as a renewal of the one before", async () => {
			const key = ecdsaKey.host()
			const issued = await certificateOf(await issueHostV4(key, ["chain.example.com"]))
			const first = await certificateOf(await renewV4(issued, key))

			const second = await certificateOf(await renewV4(first, key))

			expect(renewalOf(first.certificate.serial)).toBe(`${issued.certificate.serial}`)
			expect(renewalOf(second.certificate.serial)).toBe(`${first.certificate.serial}`)
			expect(audit(second.certificate.serial).requested_by).toBeNull()
		})

		it("should record a renewal of a certificate that was not recorded", async () => {
			const env = makeEnv({ DB: fromNodeSqlite(sqlite), PRIVATE_KEY: secretFromString(ecdsaKey.ca().privateKey) })
			const previous = hostCertificate(ecdsaKey.ca(), ecdsaKey.host())
			const renewed = hostCertificate(ecdsaKey.ca(), ecdsaKey.host())

			expect(await recordRenewal(env, previous, renewed)).toBe(true)

			expect(audit(previous.serial)).toEqual({ requested_by: null, revoked_by: "key-holder", revocation_reason: "renewal" })
			expect(audit(renewed.serial)).toEqual({ requested_by: null, revoked_by: null, revocation_reason: null })
			expect(renewalOf(renewed.serial)).toBe(`${previous.serial}`)
		})

		it("should log the revocation of the renewed certificate", async () => {
			const log = vi.spyOn(console, "log").mockImplementation(() => undefined)
			const env = makeEnv({ DB: fromNodeSqlite(sqlite), PRIVATE_KEY: secretFromString(ecdsaKey.ca().privateKey), LOG_LEVEL: "info" })
			const previous = hostCertificate(ecdsaKey.ca(), ecdsaKey.host())

			await recordRenewal(env, previous, hostCertificate(ecdsaKey.ca(), ecdsaKey.host()))

			expect(log).toHaveBeenCalledWith(expect.objectContaining({
				message: "certificate revoked",
				serial: `${previous.serial}`,
				certificate_type: "host",
				revoked_by: "key-holder",
				revocation_reason: "renewal",
			}))
		})
	})

	describe("KRL", () => {
		it("should list certificates revoked with the new columns set", async () => {
			const key = ecdsaKey.host()
			const issued = await certificateOf(await issueHostV4(key, ["krl.example.com"]))
			const renewed = await certificateOf(await renewV4(issued, key))

			const response = await ca.fetch(new Request("http://example.com/api/v4/host/krl"))
			expect(response.status).toBe(200)
			const krl = Buffer.from(KrlResponse.parse(await response.json()).krl, "base64")

			expect(isRevoked(krl, issued.text)).toBe(true)
			expect(isRevoked(krl, renewed.text)).toBe(false)
		})
	})
})

describe("migration 0004_certificate_audit", () => {
	const before = migrations.filter((m) => m.name !== "0004_certificate_audit" && m.name !== "0005_renewal_of")
	const through0004 = migrations.filter((m) => m.name !== "0005_renewal_of")

	// a database migrated to 0003 that already holds a revoked certificate
	const existing = async (): Promise<DatabaseSync> => {
		const raw = new DatabaseSync(":memory:")
		await applyMigrations(fromNodeSqlite(raw), before)
		raw.exec(`INSERT INTO certificates (serial, key_id, principals, extensions, valid_after, valid_before, revoked_at, certificate_type, public_key)
			VALUES ('1234', 'user@example.com', 'UID=user', 'permit-pty', '2026-01-01T00:00:00.000Z', '2026-01-02T00:00:00.000Z', '2026-01-01T12:00:00.000Z', 0, 'ssh-ed25519 AAAA')`)
		return raw
	}

	it("should keep existing certificates, leaving who requested and revoked them unknown", async () => {
		const raw = await existing()

		expect((await applyMigrations(fromNodeSqlite(raw), through0004)).map((m) => m.name)).toEqual(["0004_certificate_audit"])

		expect(raw.prepare("SELECT serial, key_id, revoked_at, requested_by, revoked_by, revocation_reason FROM certificates").all()).toEqual([{
			serial: "1234",
			key_id: "user@example.com",
			revoked_at: "2026-01-01T12:00:00.000Z",
			requested_by: null,
			revoked_by: null,
			revocation_reason: null,
		}])
	})

	it("should be applied once when applied concurrently", async () => {
		const raw = await existing()
		const db = fromNodeSqlite(raw)

		const applied = await Promise.all(Array.from({ length: 5 }, async () => await applyMigrations(db, through0004)))

		expect(applied.flat().map((m) => m.name)).toEqual(["0004_certificate_audit"])
		expect(raw.prepare("SELECT count(*) AS n FROM migrations WHERE name = '0004_certificate_audit'").get()).toEqual({ n: 1 })
	})
})

describe("migration 0005_renewal_of", () => {
	const before = migrations.filter((m) => m.name !== "0005_renewal_of")

	const Host = 1
	const Requester = "user@example.com"

	type Row = {
		serial: string
		publicKey?: string
		principals?: string
		requestedBy?: string | null
		/** When its validity started */
		validAfter: string
		/** When it was revoked for renewal, if it was */
		renewedAt?: string
		type?: number
	}

	// a database migrated to 0004 that holds the given certificates, recorded in order
	const existing = async (...rows: Row[]): Promise<DatabaseSync> => {
		const raw = new DatabaseSync(":memory:")
		await applyMigrations(fromNodeSqlite(raw), before)
		const insert = raw.prepare(`INSERT INTO certificates (serial, key_id, principals, extensions, valid_after, valid_before, revoked_at, certificate_type, public_key, requested_by, revoked_by, revocation_reason)
			VALUES (?, 'host', ?, '', ?, '2026-12-31T00:00:00.000Z', ?, ?, ?, ?, ?, ?)`)
		for (const row of rows) {
			insert.run(
				row.serial,
				row.principals ?? "CN=host.example.com",
				row.validAfter,
				row.renewedAt ?? null,
				row.type ?? Host,
				row.publicKey ?? "ssh-ed25519 AAAA1",
				row.requestedBy === undefined ? Requester : row.requestedBy,
				row.renewedAt === undefined ? null : "key-holder",
				row.renewedAt === undefined ? null : "renewal",
			)
		}
		return raw
	}

	const migrate = async (raw: DatabaseSync): Promise<Record<string, { requested_by: unknown, renewal_of: unknown }>> => {
		expect((await applyMigrations(fromNodeSqlite(raw), migrations)).map((m) => m.name)).toEqual(["0005_renewal_of"])
		return Object.fromEntries(raw.prepare("SELECT serial, requested_by, renewal_of FROM certificates").all()
			.map((r) => [String(r.serial), { requested_by: r.requested_by, renewal_of: r.renewal_of }]))
	}

	it("should link each renewal in a chain to what it renewed and clear its requester", async () => {
		const raw = await existing(
			{ serial: "1", validAfter: "2026-01-01T00:00:00.000Z", renewedAt: "2026-01-02T00:00:00.250Z" },
			{ serial: "2", validAfter: "2026-01-02T00:00:00.000Z", renewedAt: "2026-01-03T00:00:01.500Z" },
			{ serial: "3", validAfter: "2026-01-03T00:00:01.000Z" },
		)

		expect(await migrate(raw)).toEqual({
			"1": { requested_by: Requester, renewal_of: null },
			"2": { requested_by: null, renewal_of: "1" },
			"3": { requested_by: null, renewal_of: "2" },
		})
	})

	it.each([
		["another key", { publicKey: "ssh-ed25519 AAAA2" }],
		["other principals", { principals: "CN=other.example.com" }],
		["another requester", { requestedBy: "other@example.com" }],
		["a validity that started more than a minute before the revocation", { validAfter: "2026-01-01T23:58:00.000Z" }],
		["a validity that started after the revocation", { validAfter: "2026-01-02T00:00:01.000Z" }],
		["a user certificate", { type: 0 }],
	])("should not link a certificate with %s", async (_name, change) => {
		const raw = await existing(
			{ serial: "1", validAfter: "2026-01-01T00:00:00.000Z", renewedAt: "2026-01-02T00:00:00.250Z" },
			{ serial: "2", validAfter: "2026-01-02T00:00:00.000Z", ...change },
		)

		const rows = await migrate(raw)

		expect(rows["2"]).toEqual({ requested_by: change.requestedBy ?? Requester, renewal_of: null })
	})

	it("should not link a certificate recorded before the one revoked", async () => {
		const raw = await existing(
			{ serial: "2", validAfter: "2026-01-02T00:00:00.000Z" },
			{ serial: "1", validAfter: "2026-01-01T00:00:00.000Z", renewedAt: "2026-01-02T00:00:00.250Z" },
		)

		expect((await migrate(raw))["2"]).toEqual({ requested_by: Requester, renewal_of: null })
	})

	it("should leave certificates that cannot be told apart as they were", async () => {
		const raw = await existing(
			{ serial: "1", validAfter: "2026-01-01T00:00:00.000Z", renewedAt: "2026-01-02T00:00:00.250Z" },
			{ serial: "2", validAfter: "2026-01-02T00:00:00.000Z" },
			{ serial: "3", validAfter: "2026-01-02T00:00:00.000Z" },
		)

		expect(await migrate(raw)).toEqual({
			"1": { requested_by: Requester, renewal_of: null },
			"2": { requested_by: Requester, renewal_of: null },
			"3": { requested_by: Requester, renewal_of: null },
		})
	})
})
