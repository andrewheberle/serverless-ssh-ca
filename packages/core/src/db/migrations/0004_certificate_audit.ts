import type { Migration } from "../migrate.js"

export const migration: Migration = {
	name: "0004_certificate_audit",
	statements: [
		// who asked for the certificate, as the email address of the requester.
		// Certificates recorded before this migration are left NULL as who
		// asked for them is not known
		"ALTER TABLE certificates ADD COLUMN requested_by TEXT",
		// who revoked the certificate, such as "key-holder", and why, such as
		// "renewal". Both are NULL for a certificate that is not revoked or
		// was revoked before this migration
		"ALTER TABLE certificates ADD COLUMN revoked_by TEXT",
		"ALTER TABLE certificates ADD COLUMN revocation_reason TEXT",
	]
}
