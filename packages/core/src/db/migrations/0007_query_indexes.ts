import type { Migration } from "../migrate.js"

export const migration: Migration = {
	name: "0007_query_indexes",
	statements: [
		// indexes no query can use: serial is already indexed by its UNIQUE
		// constraint, nothing filters on valid_after, every comparison wraps
		// valid_before in unixepoch(), and revoked_at alone is never chosen
		"DROP INDEX IF EXISTS idx_certificates_serial",
		"DROP INDEX IF EXISTS idx_certificates_valid_after",
		"DROP INDEX IF EXISTS idx_certificates_valid_before",
		"DROP INDEX IF EXISTS idx_certificates_revoked_at",
		// the revoked certificates of a type, by when they expire, so a KRL
		// reads only the certificates it contains. The expression must match
		// the one in the KRL query for the index to be used
		"CREATE INDEX IF NOT EXISTS idx_certificates_krl ON certificates(certificate_type, unixepoch(valid_before,'subsec')) WHERE revoked_at IS NOT NULL",
		// the renewal of a certificate, which is looked up with its type. This
		// replaces the index on renewal_of alone, which the query planner only
		// chooses over the certificate_type index once statistics are gathered
		"CREATE INDEX IF NOT EXISTS idx_certificates_renewed_as ON certificates(renewal_of, certificate_type)",
		"DROP INDEX IF EXISTS idx_certificates_renewal_of",
	]
}
