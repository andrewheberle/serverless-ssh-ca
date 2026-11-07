import type { Migration } from "../migrate.js"

export const migration: Migration = {
	name: "0006_client_address",
	statements: [
		// the client address of the request that issued or renewed the
		// certificate, and of the request a key holder revoked it with. Both
		// are NULL when the address was not known, for a revocation by an
		// admin, and for certificates recorded before this migration
		"ALTER TABLE certificates ADD COLUMN request_address TEXT",
		"ALTER TABLE certificates ADD COLUMN revocation_address TEXT",
	]
}
