import type { Migration } from "../migrate.js"

export const migration: Migration = {
	name: "0003_krl_revision",
	statements: [
		// incremented whenever a certificate is revoked, so a cached KRL can be
		// keyed by the revision it was generated for
		"ALTER TABLE krl ADD COLUMN revision INTEGER NOT NULL DEFAULT 0",
	]
}
