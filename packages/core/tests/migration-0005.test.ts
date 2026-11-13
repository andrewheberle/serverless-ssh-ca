import { describe, expect, it } from "vitest"
import { DatabaseSync } from "node:sqlite"
import { applyMigrations, type Migration } from "../src/db/migrate.js"
import { migrations } from "../src/db/migrations/index.js"
import { migration } from "../src/db/migrations/0005_renewal_of.js"
import { fromNodeSqlite } from "../src/node/index.js"

// migration 0005 as it was first released, which took time in proportion to
// the square of the number of host certificates. Its SQL was rewritten to run
// in linear time (#579), and must still give exactly the same result
const reference: Migration = {
	name: "0005_renewal_of",
	statements: [
		"ALTER TABLE certificates ADD COLUMN renewal_of TEXT",
		"CREATE INDEX IF NOT EXISTS idx_certificates_renewal_of ON certificates(renewal_of)",
		`WITH matches AS (
			SELECT renewed.id AS renewed_id, previous.serial AS previous_serial
			FROM certificates AS renewed
			JOIN certificates AS previous
				ON previous.certificate_type = 1
				AND previous.revocation_reason = 'renewal'
				AND previous.id < renewed.id
				AND previous.public_key = renewed.public_key
				AND previous.principals = renewed.principals
				AND previous.requested_by IS renewed.requested_by
				AND unixepoch(previous.revoked_at, 'subsec') >= unixepoch(renewed.valid_after, 'subsec')
				AND unixepoch(previous.revoked_at, 'subsec') < unixepoch(renewed.valid_after, 'subsec', '+15 seconds')
			WHERE renewed.certificate_type = 1
		),
		unique_matches AS (
			SELECT renewed_id, previous_serial FROM matches
			WHERE renewed_id IN (SELECT renewed_id FROM matches GROUP BY renewed_id HAVING count(*) = 1)
			AND previous_serial IN (SELECT previous_serial FROM matches GROUP BY previous_serial HAVING count(*) = 1)
		)
		UPDATE certificates
		SET renewal_of = (SELECT previous_serial FROM unique_matches WHERE renewed_id = certificates.id)
		WHERE id IN (SELECT renewed_id FROM unique_matches)`,
		"UPDATE certificates SET requested_by = NULL WHERE renewal_of IS NOT NULL",
	],
}

const before = migrations.filter((m) => m.name !== "0005_renewal_of" && m.name !== "0006_client_address")

const Host = 1
const User = 0

type Row = {
	serial: string
	publicKey: string
	principals: string
	requestedBy: string | null
	type: number
	validAfter: string
	revokedAt: string | null
	revocationReason: string | null
}

type Result = { serial: string, requested_by: string | null, renewal_of: string | null }[]

// a database migrated to 0004 holding the given certificates, recorded in order
const existing = async (rows: Row[]): Promise<DatabaseSync> => {
	const raw = new DatabaseSync(":memory:")
	await applyMigrations(fromNodeSqlite(raw), before)
	const insert = raw.prepare(`INSERT INTO certificates (serial, key_id, principals, extensions, valid_after, valid_before, revoked_at, certificate_type, public_key, requested_by, revoked_by, revocation_reason)
		VALUES (?, 'host', ?, '', ?, '2027-12-31T00:00:00.000Z', ?, ?, ?, ?, ?, ?)`)
	raw.exec("BEGIN")
	for (const row of rows) {
		insert.run(row.serial, row.principals, row.validAfter, row.revokedAt, row.type, row.publicKey, row.requestedBy,
			row.revocationReason === null ? null : "key-holder", row.revocationReason)
	}
	raw.exec("COMMIT")
	return raw
}

// the rows that migration 0005 sets, once it has been applied
const migrated = async (rows: Row[], migration0005: Migration): Promise<Result> => {
	const raw = await existing(rows)
	expect((await applyMigrations(fromNodeSqlite(raw), [migration0005])).map((m) => m.name)).toEqual(["0005_renewal_of"])
	const result = raw.prepare("SELECT serial, requested_by, renewal_of FROM certificates ORDER BY id").all() as Result
	raw.close()
	return result
}

const expectSameResult = async (rows: Row[]): Promise<Result> => {
	const result = await migrated(rows, migration)
	expect(result).toEqual(await migrated(rows, reference))
	return result
}

const at = (base: number, offsetMs: number): string => new Date(base + offsetMs).toISOString()

const day = 24 * 60 * 60 * 1000
const start = Date.parse("2026-01-01T00:00:00.000Z")

const row = (overrides: Partial<Row> & Pick<Row, "serial" | "validAfter">): Row => ({
	publicKey: "ssh-ed25519 AAAA1",
	principals: "host.example.com",
	requestedBy: "user@example.com",
	type: Host,
	revokedAt: null,
	revocationReason: null,
	...overrides,
})

// a deterministic pseudo-random number generator, so a failure can be repeated
const mulberry32 = (seed: number) => (): number => {
	let t = (seed += 0x6D2B79F5)
	t = Math.imul(t ^ (t >>> 15), t | 1)
	t ^= t + Math.imul(t ^ (t >>> 7), t | 61)
	return ((t ^ (t >>> 14)) >>> 0) / 4294967296
}

describe("migration 0005_renewal_of", () => {
	it.each([
		["a chain of renewals", [
			row({ serial: "1", validAfter: at(start, 0), revokedAt: at(start, day + 250), revocationReason: "renewal" }),
			row({ serial: "2", validAfter: at(start, day), revokedAt: at(start, 2 * day + 1500), revocationReason: "renewal" }),
			row({ serial: "3", validAfter: at(start, 2 * day + 1000) }),
		]],
		["a revocation at the same moment the renewal's validity started", [
			row({ serial: "1", validAfter: at(start, 0), revokedAt: at(start, day), revocationReason: "renewal" }),
			row({ serial: "2", validAfter: at(start, day) }),
		]],
		["a revocation just under and exactly 15 seconds after the renewal's validity started", [
			row({ serial: "1", validAfter: at(start, 0), revokedAt: at(start, day + 14_999), revocationReason: "renewal" }),
			row({ serial: "2", validAfter: at(start, day) }),
			row({ serial: "3", publicKey: "ssh-ed25519 AAAA2", validAfter: at(start, 0), revokedAt: at(start, day + 15_000), revocationReason: "renewal" }),
			row({ serial: "4", publicKey: "ssh-ed25519 AAAA2", validAfter: at(start, day) }),
		]],
		["two renewals that could be of the same certificate", [
			row({ serial: "1", validAfter: at(start, 0), revokedAt: at(start, day + 500), revocationReason: "renewal" }),
			row({ serial: "2", validAfter: at(start, day) }),
			row({ serial: "3", validAfter: at(start, day + 100) }),
		]],
		["two certificates that could have been renewed by the same renewal", [
			row({ serial: "1", validAfter: at(start, 0), revokedAt: at(start, day + 500), revocationReason: "renewal" }),
			row({ serial: "2", validAfter: at(start, 10), revokedAt: at(start, day + 600), revocationReason: "renewal" }),
			row({ serial: "3", validAfter: at(start, day) }),
		]],
		["requesters that are not set", [
			row({ serial: "1", requestedBy: null, validAfter: at(start, 0), revokedAt: at(start, day + 250), revocationReason: "renewal" }),
			row({ serial: "2", requestedBy: null, validAfter: at(start, day) }),
			row({ serial: "3", publicKey: "ssh-ed25519 AAAA2", requestedBy: null, validAfter: at(start, 0), revokedAt: at(start, day + 250), revocationReason: "renewal" }),
			row({ serial: "4", publicKey: "ssh-ed25519 AAAA2", validAfter: at(start, day) }),
		]],
		["certificates that are not host certificates renewed", [
			row({ serial: "1", type: User, validAfter: at(start, 0), revokedAt: at(start, day + 250), revocationReason: "renewal" }),
			row({ serial: "2", validAfter: at(start, day) }),
			row({ serial: "3", publicKey: "ssh-ed25519 AAAA2", validAfter: at(start, 0), revokedAt: at(start, day + 250), revocationReason: "key compromised" }),
			row({ serial: "4", publicKey: "ssh-ed25519 AAAA2", validAfter: at(start, day) }),
			row({ serial: "5", publicKey: "ssh-ed25519 AAAA3", validAfter: at(start, 0), revokedAt: at(start, day + 250), revocationReason: "renewal" }),
			row({ serial: "6", publicKey: "ssh-ed25519 AAAA3", type: User, validAfter: at(start, day) }),
		]],
		["a renewal recorded before the certificate it would have renewed", [
			row({ serial: "1", validAfter: at(start, day) }),
			row({ serial: "2", validAfter: at(start, 0), revokedAt: at(start, day + 250), revocationReason: "renewal" }),
		]],
	])("should give the same result as when first released for %s", async (_name, rows) => {
		await expectSameResult(rows)
	})

	it("should link a chain of renewals and clear their requesters", async () => {
		const result = await expectSameResult([
			row({ serial: "1", validAfter: at(start, 0), revokedAt: at(start, day + 250), revocationReason: "renewal" }),
			row({ serial: "2", validAfter: at(start, day), revokedAt: at(start, 2 * day + 1500), revocationReason: "renewal" }),
			row({ serial: "3", validAfter: at(start, 2 * day + 1000) }),
		])

		expect(result).toEqual([
			{ serial: "1", requested_by: "user@example.com", renewal_of: null },
			{ serial: "2", requested_by: null, renewal_of: "1" },
			{ serial: "3", requested_by: null, renewal_of: "2" },
		])
	})

	it.each([1, 2, 3, 4, 5])("should give the same result as when first released for random certificates (seed %d)", async (seed) => {
		const random = mulberry32(seed)
		const pick = <T>(values: readonly T[]): T => values[Math.floor(random() * values.length)] as T
		const keys = ["ssh-ed25519 AAAA1", "ssh-ed25519 AAAA2", "ssh-ed25519 AAAA3", "ssh-ed25519 AAAA4"]
		const principals = ["a.example.com", "b.example.com", "a.example.com,b.example.com"]
		const requesters = ["user@example.com", "other@example.com", null]
		// gaps between a renewal's validity starting and the revocation of what
		// it renewed, around the 15 second window
		const gaps = [-1000, 0, 250, 14_999, 15_000, 20_000]

		const rows: Row[] = []
		for (let i = 0; i < 3000; i++) {
			const renewed = random() < 0.6
			rows.push(row({
				serial: `${i + 1}`,
				publicKey: pick(keys),
				principals: pick(principals),
				requestedBy: pick(requesters),
				type: random() < 0.9 ? Host : User,
				validAfter: at(start, Math.floor(random() * 60) * day),
				revokedAt: renewed ? at(start, Math.floor(random() * 60) * day + pick(gaps)) : null,
				revocationReason: renewed ? (random() < 0.9 ? "renewal" : "key compromised") : null,
			}))
		}

		const result = await expectSameResult(rows)
		// the random certificates match some renewals, so the comparison is not of nothing
		expect(result.some((r) => r.renewal_of !== null)).toBe(true)
	}, 60_000)

	it("should match the certificates that could have been renewed through an index", async () => {
		const raw = await existing([])
		raw.exec("ALTER TABLE certificates ADD COLUMN renewal_of TEXT")
		const [createIndex, match] = migration.statements.filter((s) => s.includes("tmp_0005_renewal_candidates"))
		if (createIndex === undefined || match === undefined) {
			throw new Error("missing statements")
		}
		raw.exec(createIndex)

		const plan = (raw.prepare(`EXPLAIN QUERY PLAN ${match}`).all() as { detail: string }[]).map((r) => r.detail)

		expect(plan).toContainEqual(expect.stringMatching(/^SEARCH previous USING INDEX tmp_0005_renewal_candidates \(public_key=\? AND principals=\?/))
		expect(plan.filter((d) => /^SCAN previous\b/.test(d))).toEqual([])
		raw.close()
	})

	it("should drop the index it creates for the match", async () => {
		const raw = await existing([row({ serial: "1", validAfter: at(start, 0) })])
		await applyMigrations(fromNodeSqlite(raw), [migration])

		expect(raw.prepare("SELECT name FROM sqlite_master WHERE name = 'tmp_0005_renewal_candidates'").all()).toEqual([])
		raw.close()
	})

	it("should migrate 20,000 host certificates renewed every day in linear time", async () => {
		// 200 hosts renewed every day for 100 days, as a CA that keeps a year of
		// certificates may have, which the first release took minutes to match
		const rows: Row[] = []
		for (let host = 0; host < 200; host++) {
			for (let d = 0; d < 100; d++) {
				const last = d === 99
				rows.push(row({
					serial: `${host * 100 + d + 1}`,
					publicKey: `ssh-ed25519 AAAA${host}`,
					principals: `host${host}.example.com`,
					validAfter: at(start, d * day),
					revokedAt: last ? null : at(start, (d + 1) * day + 250),
					revocationReason: last ? null : "renewal",
				}))
			}
		}

		const begin = performance.now()
		const result = await migrated(rows, migration)
		const elapsed = performance.now() - begin

		expect(result.filter((r) => r.renewal_of !== null)).toHaveLength(200 * 99)
		// generous, so a slow machine does not fail it, but far below the time
		// the first release took
		expect(elapsed).toBeLessThan(20_000)
	}, 60_000)
})
