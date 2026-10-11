import type { Migration } from "../migrate.js"

export const migration: Migration = {
	name: "0002_krl_version",
	statements: [
		`CREATE TABLE IF NOT EXISTS krl (
			certificate_type INTEGER PRIMARY KEY,
			version INTEGER NOT NULL,
			digest TEXT,
			updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL
		)`,
		// KRLs were previously always version 1 and have no digest, so the
		// first KRL generated after this migration is version 2
		"INSERT OR IGNORE INTO krl (certificate_type, version, digest) VALUES (0, 1, NULL), (1, 1, NULL)",
	]
}
