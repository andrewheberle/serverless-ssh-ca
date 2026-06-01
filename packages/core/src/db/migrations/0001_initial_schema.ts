import { type Migration } from "workers-qb";

export const migration: Migration = {
	name: "0001_initial_schema",
	sql: `
		CREATE TABLE IF NOT EXISTS certificates (
			id INTEGER PRIMARY KEY,
			serial TEXT UNIQUE NOT NULL,
			key_id TEXT NOT NULL,
			principals TEXT NOT NULL,
			extensions TEXT,
			valid_after TIMESTAMP NOT NULL,
			valid_before TIMESTAMP NOT NULL,
			revoked_at TIMESTAMP,
			certificate_type INTEGER NOT NULL DEFAULT 0,
			public_key TEXT
		);

		CREATE INDEX IF NOT EXISTS idx_certificates_serial ON certificates(serial);
		CREATE INDEX IF NOT EXISTS idx_certificates_valid_after ON certificates(valid_after);
		CREATE INDEX IF NOT EXISTS idx_certificates_valid_before ON certificates(valid_before);
		CREATE INDEX IF NOT EXISTS idx_certificates_revoked_at ON certificates(revoked_at);
		CREATE INDEX IF NOT EXISTS idx_certificates_certificate_type ON certificates(certificate_type);
	`
}
