import z from "zod"
import type { CaDatabase } from "../types.js"

/**
 * A database schema migration.
 *
 * Migrations are applied in order and recorded by `name` in the `migrations`
 * table, so a name must never change once released. Each statement must be a
 * single SQL statement.
 */
export type Migration = {
	/** Unique name recorded once the migration has been applied */
	name: string
	/** The SQL statements to run, in order, as one transaction */
	statements: string[]
}

// matches the table previously created by workers-qb so existing databases are not migrated again
const createMigrationsTable = `CREATE TABLE IF NOT EXISTS migrations (
	id         INTEGER PRIMARY KEY AUTOINCREMENT,
	name       TEXT UNIQUE,
	applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL
)`

const MigrationRows = z.array(z.object({ name: z.string() }))

const appliedNames = async (db: CaDatabase): Promise<Set<string>> => {
	const { results } = await db.prepare("SELECT name FROM migrations").all()
	return new Set(MigrationRows.parse(results).map(row => row.name))
}

const isApplied = async (db: CaDatabase, name: string): Promise<boolean> => {
	const { results } = await db.prepare("SELECT name FROM migrations WHERE name = ?").bind(name).all()
	return results.length > 0
}

/**
 * Apply any migrations that have not yet been applied to the database.
 *
 * Each migration is run with {@link CaDatabase.batch} so it applies atomically,
 * and its row in the `migrations` table is inserted first. When several callers
 * race to apply the same migration only one succeeds; the others fail on that
 * insert before running any of the migration's statements and their batch rolls
 * back, so migrations that are not idempotent are safe to apply concurrently.
 *
 * @param db The database to migrate, see {@link CaDatabase}
 * @param migrations The migrations to apply in order, see {@link Migration}
 * @returns The migrations applied by this call, excluding any applied concurrently by another caller
 */
export const applyMigrations = async (db: CaDatabase, migrations: readonly Migration[]): Promise<Migration[]> => {
	await db.prepare(createMigrationsTable).run()
	const existing = await appliedNames(db)

	const applied: Migration[] = []
	for (const migration of migrations) {
		if (existing.has(migration.name)) {
			continue
		}

		try {
			await db.batch([
				db.prepare("INSERT INTO migrations (name) VALUES (?)").bind(migration.name),
				...migration.statements.map(sql => db.prepare(sql)),
			])
			applied.push(migration)
		} catch (err) {
			// another caller applying the same migration is not an error
			if (!(await isApplied(db, migration.name))) {
				throw err
			}
		}
	}

	return applied
}

const migrated = new WeakMap<CaDatabase, Promise<Migration[]>>()

/**
 * Apply migrations to a database at most once per database binding, see
 * {@link applyMigrations}.
 *
 * Concurrent and later callers share the result of the first call, unless it
 * fails, in which case the next call tries again.
 *
 * @param db The database to migrate, see {@link CaDatabase}
 * @param migrations The migrations to apply in order, see {@link Migration}
 * @returns The migrations applied, or an empty array if this database binding has already been migrated
 */
export const migrateOnce = async (db: CaDatabase, migrations: readonly Migration[]): Promise<Migration[]> => {
	const pending = migrated.get(db)
	if (pending !== undefined) {
		await pending
		return []
	}

	const result = applyMigrations(db, migrations)
	migrated.set(db, result)
	try {
		return await result
	} catch (err) {
		if (migrated.get(db) === result) {
			migrated.delete(db)
		}
		throw err
	}
}
