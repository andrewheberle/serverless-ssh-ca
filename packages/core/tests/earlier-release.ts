import type { Migration } from "../src/db/migrate.js"
import { migrations } from "../src/db/migrations/index.js"

// the position of a migration in the list the CA applies
const indexOf = (name: string): number => {
	const index = migrations.findIndex((m) => m.name === name)
	if (index === -1) {
		throw new Error(`unknown migration ${name}`)
	}
	return index
}

/**
 * The migrations a database recorded by the last release before `name` was
 * added has applied, which are those before it in the list the CA applies.
 * Applying the whole list to such a database upgrades it as the CA does.
 *
 * @param name The name of a migration
 * @returns The migrations before it
 */
export const migrationsBefore = (name: string): Migration[] => migrations.slice(0, indexOf(name))

/**
 * The names of the migrations applied when a database from before `name` is
 * upgraded, see {@link migrationsBefore}, which are it and those after it.
 *
 * @param name The name of a migration
 * @returns The names of it and the migrations after it
 */
export const namesFrom = (name: string): string[] => migrations.slice(indexOf(name)).map((m) => m.name)
