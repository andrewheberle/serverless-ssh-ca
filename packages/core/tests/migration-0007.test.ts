import { describe, it, expect } from "vitest"
import { DatabaseSync } from "node:sqlite"
import { applyMigrations } from "../src/db/migrate.js"
import { migrations } from "../src/db/migrations/index.js"
import { migrationsBefore, namesFrom } from "./earlier-release.js"
import { migration } from "../src/db/migrations/0007_query_indexes.js"
import { getRenewalLinks, getRevocationList } from "../src/db/index.js"
import { fromNodeSqlite } from "../src/node/sqlite.js"
import { CertificateType } from "../src/db/types.js"
import type { CaDatabase } from "../src/types.js"
import { makeEnv } from "./env.js"

// the indexes on the certificates table, other than the one for its UNIQUE constraint
const indexes = (raw: DatabaseSync): unknown[] =>
	raw.prepare("SELECT name FROM sqlite_master WHERE type = 'index' AND tbl_name = 'certificates' AND sql IS NOT NULL ORDER BY name").all().map((r) => r.name)

// a database that records the SQL of the queries it prepares
const recording = (db: CaDatabase): { db: CaDatabase, prepared: string[] } => {
	const prepared: string[] = []
	return {
		prepared,
		db: {
			prepare: (query) => {
				prepared.push(query)
				return db.prepare(query)
			},
			batch: (statements) => db.batch(statements),
			exec: (query) => db.exec(query),
		},
	}
}

// the query plan of a query, which does not depend on the values it is run with,
// so its parameters are left NULL. No ANALYZE is run, as the CA never runs it
const planOf = (raw: DatabaseSync, sql: string): string[] =>
	raw.prepare(`EXPLAIN QUERY PLAN ${sql}`).all().map((r) => String(r.detail))

const hoursFromNow = (hours: number): string => new Date(Date.now() + hours * 60 * 60 * 1000).toISOString()

const insert = (raw: DatabaseSync, serial: string, type: CertificateType, validBefore: string, revoked: boolean, renewalOf: string | null = null): void => {
	raw.prepare("INSERT INTO certificates (serial, key_id, principals, valid_after, valid_before, revoked_at, certificate_type, renewal_of) VALUES (?, ?, ?, ?, ?, ?, ?, ?)")
		.run(serial, "key", "CN=host", "2000-01-01T00:00:00.000Z", validBefore, revoked ? "2000-01-01T00:00:00.000Z" : null, type, renewalOf)
}

const migrated = async (): Promise<DatabaseSync> => {
	const raw = new DatabaseSync(":memory:")
	await applyMigrations(fromNodeSqlite(raw), migrations)
	return raw
}

describe("migration 0007_query_indexes", () => {
	it("should leave only the indexes the CA's queries use", async () => {
		const raw = await migrated()

		expect(indexes(raw)).toEqual([
			"idx_certificates_certificate_type",
			"idx_certificates_krl",
			"idx_certificates_renewed_as",
		])
		raw.close()
	})

	it("should upgrade a database recorded by an earlier release without changing its certificates", async () => {
		const raw = new DatabaseSync(":memory:")
		await applyMigrations(fromNodeSqlite(raw), migrationsBefore(migration.name))
		insert(raw, "1", CertificateType.Host, hoursFromNow(1), true)
		insert(raw, "2", CertificateType.Host, hoursFromNow(1), false, "1")
		const before = raw.prepare("SELECT * FROM certificates ORDER BY id").all()

		expect((await applyMigrations(fromNodeSqlite(raw), migrations)).map((m) => m.name)).toEqual(namesFrom(migration.name))

		expect(raw.prepare("SELECT * FROM certificates ORDER BY id").all()).toEqual(before)
		expect(indexes(raw)).toContain("idx_certificates_krl")
		raw.close()
	})

	it("should search the KRL index for the certificates in a KRL", async () => {
		const raw = await migrated()
		const { db, prepared } = recording(fromNodeSqlite(raw))

		await getRevocationList(makeEnv({ DB: db }), CertificateType.User)
		const [query] = prepared.filter((sql) => sql.includes("revoked_at NOTNULL"))
		if (query === undefined) {
			throw new Error("the KRL query was not prepared")
		}

		expect(planOf(raw, query)).toEqual(["SEARCH certificates USING INDEX idx_certificates_krl (certificate_type=? AND <expr>>?)"])
		raw.close()
	})

	it("should search the renewed as index for the renewal of a host certificate", async () => {
		const raw = await migrated()
		const { db, prepared } = recording(fromNodeSqlite(raw))

		await getRenewalLinks(makeEnv({ DB: db }), { serial: "1", certificate_type: CertificateType.Host, renewal_of: null })
		const [query] = prepared.filter((sql) => sql.includes("renewal_of = ?"))
		if (query === undefined) {
			throw new Error("the renewed as query was not prepared")
		}

		expect(planOf(raw, query)).toEqual(["SEARCH certificates USING INDEX idx_certificates_renewed_as (renewal_of=? AND certificate_type=?)"])
		raw.close()
	})
})

describe("the KRL query", () => {
	it("should list the revoked certificates of a type until 24 hours after they expire", async () => {
		const raw = await migrated()
		insert(raw, "1", CertificateType.User, hoursFromNow(1), true)
		insert(raw, "2", CertificateType.User, hoursFromNow(-23.9), true)
		insert(raw, "3", CertificateType.User, hoursFromNow(-24.1), true)
		insert(raw, "4", CertificateType.User, hoursFromNow(1), false)
		insert(raw, "5", CertificateType.Host, hoursFromNow(1), true)

		const serials = await getRevocationList(makeEnv({ DB: fromNodeSqlite(raw) }), CertificateType.User)

		expect(serials.toSorted()).toEqual(["1", "2"])
		// the same certificates as the condition the query was written with before 0007
		expect(raw.prepare("SELECT serial FROM certificates WHERE revoked_at NOTNULL AND certificate_type = ? AND unixepoch('subsec') < unixepoch(valid_before,'subsec','24 hours') ORDER BY serial").all(CertificateType.User).map((r) => r.serial)).toEqual(["1", "2"])
		raw.close()
	})
})
