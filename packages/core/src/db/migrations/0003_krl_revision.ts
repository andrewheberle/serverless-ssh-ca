import type { Migration } from "../migrate.js"

export const migration: Migration = {
	name: "0003_krl_revision",
	statements: [
		// incremented whenever a certificate is revoked, so a cached KRL can be
		// keyed by the revision it was generated for
		"ALTER TABLE krl ADD COLUMN revision INTEGER NOT NULL DEFAULT 0",
		// KRLs were previously generated at the time of each request, but are
		// now generated at the time their version last changed. Starting each
		// version again from now ensures a KRL fetched before this migration
		// is never newer than the same version fetched afterwards.
		"UPDATE krl SET updated_at = CURRENT_TIMESTAMP",
	]
}
