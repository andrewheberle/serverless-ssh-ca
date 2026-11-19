/**
 * Database types used by workers-qb to type queries.
 *
 * These must match the schema created by the migrations in `./migrations`, so
 * update them with any change to the database.
 *
 * Timestamps are stored as text, so are typed as strings. The CA writes them as
 * ISO 8601 in UTC, such as `2026-11-16T00:06:00.453Z`, while those set by
 * SQLite's `CURRENT_TIMESTAMP` are `YYYY-MM-DD HH:MM:SS` in UTC, such as
 * `2026-11-16 00:06:00`.
 */

/** The type of certificate, as stored in the `certificate_type` column */
export enum CertificateType {
	User,
	Host
}

/** A row in the `certificates` table */
export type CertificateRecord = {
	id: number
	serial: string
	key_id: string
	principals: string
	extensions: string | null
	/** When the certificate became valid, as ISO 8601 */
	valid_after: string
	/** When the certificate stops being valid, as ISO 8601 */
	valid_before: string
	/** When the certificate was revoked, as ISO 8601, or null if it is not revoked */
	revoked_at: string | null
	certificate_type: CertificateType
	public_key: string | null
	/** The email address of the requester who asked for the certificate, or null if it is a renewal or not known */
	requested_by: string | null
	/** The serial of the host certificate this certificate is a renewal of, or null if it is not a renewal or not known */
	renewal_of: string | null
	/** Who revoked the certificate, such as "key-holder", or null if it is not revoked or not known */
	revoked_by: string | null
	/** Why the certificate was revoked, such as "renewal", or null if no reason was given */
	revocation_reason: string | null
	/** The client address of the request that issued or renewed the certificate, or null if not known */
	request_address: string | null
	/** The client address of the request its key holder revoked it with, or null if it is not revoked, was revoked by an admin, or not known */
	revocation_address: string | null
}

/** A row in the `krl` table, holding the current version of the KRL for a {@link CertificateType} */
export type KrlRecord = {
	certificate_type: CertificateType
	version: number
	digest: string | null
	/**
	 * When the current version was first generated, as ISO 8601 when the CA set
	 * it or `YYYY-MM-DD HH:MM:SS` when it was set by `CURRENT_TIMESTAMP` in a
	 * migration and has not changed since
	 */
	updated_at: string
	/** Incremented whenever a certificate of this type is revoked */
	revision: number
}

/** A row in the `migrations` table, recording a migration that has been applied */
export type MigrationRecord = {
	id: number
	/**
	 * The name of the migration. The CA always records one, but the column
	 * does not forbid NULL, as it matches the table workers-qb created
	 */
	name: string | null
	/** When the migration was applied, as `YYYY-MM-DD HH:MM:SS` set by `CURRENT_TIMESTAMP` */
	applied_at: string
}

/** The tables in the database, used to type queries made with workers-qb */
export type DatabaseSchema = {
	certificates: CertificateRecord
	krl: KrlRecord
	migrations: MigrationRecord
}
