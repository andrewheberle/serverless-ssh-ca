import { describe, it, expect } from "vitest"
import { DatabaseSync } from "node:sqlite"
import { applyMigrations, migrateOnce, type Migration } from "../src/db/migrate.js"
import { migrations } from "../src/db/migrations/index.js"
import { isRevoked } from "../src/db/index.js"
import { fromNodeSqlite } from "../src/node/sqlite.js"
import type { CaDatabase } from "../src/types.js"
import { makeEnv } from "./env.js"

const fresh = (): { raw: DatabaseSync, db: CaDatabase } => {
	const raw = new DatabaseSync(":memory:")
	return { raw, db: fromNodeSqlite(raw) }
}

const recorded = (raw: DatabaseSync): unknown[] =>
	raw.prepare("SELECT name FROM migrations ORDER BY id").all().map(r => r.name)

const columns = (raw: DatabaseSync, table: string): unknown[] =>
	raw.prepare(`PRAGMA table_info(${table})`).all().map(r => r.name)

// the second migration is not idempotent so applying it twice fails
const testMigrations: Migration[] = [
	{ name: "0001_test", statements: ["CREATE TABLE IF NOT EXISTS t (id INTEGER PRIMARY KEY)"] },
	{ name: "0002_test", statements: ["ALTER TABLE t ADD COLUMN extra TEXT"] },
]

// a database that counts the statements it prepares
const counting = (db: CaDatabase): { db: CaDatabase, prepared: string[] } => {
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

describe("applyMigrations", () => {
	it("should apply migrations in order and record them", async () => {
		const { raw, db } = fresh()

		const applied = await applyMigrations(db, testMigrations)

		expect(applied.map(m => m.name)).toEqual(["0001_test", "0002_test"])
		expect(recorded(raw)).toEqual(["0001_test", "0002_test"])
		expect(columns(raw, "t")).toEqual(["id", "extra"])
	})

	it("should not apply migrations that are already recorded", async () => {
		const { raw, db } = fresh()
		await applyMigrations(db, testMigrations)

		const applied = await applyMigrations(db, testMigrations)

		expect(applied).toEqual([])
		expect(recorded(raw)).toEqual(["0001_test", "0002_test"])
	})

	it("should apply each migration once when run concurrently", async () => {
		const { raw, db } = fresh()

		const results = await Promise.all(Array.from({ length: 10 }, () => applyMigrations(db, testMigrations)))

		const counts = results.flat().reduce<Record<string, number>>((acc, m) => ({ ...acc, [m.name]: (acc[m.name] ?? 0) + 1 }), {})
		expect(counts).toEqual({ "0001_test": 1, "0002_test": 1 })
		expect(recorded(raw)).toEqual(["0001_test", "0002_test"])
		expect(columns(raw, "t")).toEqual(["id", "extra"])
	})

	it("should roll back and not record a migration that fails", async () => {
		const { raw, db } = fresh()
		const failing: Migration[] = [
			{ name: "0001_failing", statements: ["CREATE TABLE a (x)", "INSERT INTO missing (x) VALUES (1)"] },
		]

		await expect(applyMigrations(db, failing)).rejects.toThrow(/no such table: missing/)

		expect(recorded(raw)).toEqual([])
		expect(raw.prepare("SELECT name FROM sqlite_master WHERE name = 'a'").all()).toEqual([])
	})

	it("should not migrate again a database migrated by workers-qb", async () => {
		const { raw, db } = fresh()
		// the table and row as previously created by workers-qb
		raw.exec(`CREATE TABLE migrations (
			id         INTEGER PRIMARY KEY AUTOINCREMENT,
			name       TEXT UNIQUE,
			applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL
		)`)
		raw.exec("INSERT INTO migrations (name) VALUES ('0001_initial_schema')")

		const applied = await applyMigrations(db, migrations)

		expect(applied).toEqual([])
		expect(raw.prepare("SELECT name FROM sqlite_master WHERE name = 'certificates'").all()).toEqual([])
	})

	it("should create the certificates schema", async () => {
		const { raw, db } = fresh()

		await applyMigrations(db, migrations)

		expect(recorded(raw)).toEqual(["0001_initial_schema"])
		expect(columns(raw, "certificates")).toEqual([
			"id", "serial", "key_id", "principals", "extensions", "valid_after",
			"valid_before", "revoked_at", "certificate_type", "public_key",
		])
	})
})

describe("migrateOnce", () => {
	it("should only migrate a database once", async () => {
		const { raw, db: inner } = fresh()
		const { db, prepared } = counting(inner)

		const first = await Promise.all([migrateOnce(db, testMigrations), migrateOnce(db, testMigrations)])
		const before = prepared.length
		const later = await migrateOnce(db, testMigrations)

		expect(first.flat().map(m => m.name)).toEqual(["0001_test", "0002_test"])
		expect(later).toEqual([])
		expect(prepared.length).toBe(before)
		expect(recorded(raw)).toEqual(["0001_test", "0002_test"])
	})

	it("should try again after a failure", async () => {
		const { raw, db } = fresh()
		raw.exec("CREATE TABLE t (id INTEGER PRIMARY KEY, extra TEXT)")

		// 0002_test fails as the column already exists
		await expect(migrateOnce(db, testMigrations)).rejects.toThrow(/duplicate column/)

		raw.exec("ALTER TABLE t DROP COLUMN extra")
		const applied = await migrateOnce(db, testMigrations)

		expect(applied.map(m => m.name)).toEqual(["0002_test"])
		expect(recorded(raw)).toEqual(["0001_test", "0002_test"])
	})
})

describe("concurrent first use of a database", () => {
	it("should not fail when queries race to migrate a fresh database", async () => {
		const env = makeEnv({ DB: fresh().db })

		const results = await Promise.allSettled(Array.from({ length: 10 }, () => isRevoked(env, 1n)))

		expect(results.filter(r => r.status === "rejected")).toEqual([])
	})
})
