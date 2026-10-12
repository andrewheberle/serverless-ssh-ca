/**
 * Database types used by workers-qb to type queries.
 *
 * These must match the schema created by the migrations in `./migrations`, so
 * update them with any change to the database.
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
	valid_after: Date
	valid_before: Date
	revoked_at: Date | null
	certificate_type: CertificateType
	public_key: string | null
}

/** A row in the `krl` table, holding the current version of the KRL for a {@link CertificateType} */
export type KrlRecord = {
	certificate_type: CertificateType
	version: number
	digest: string | null
	updated_at: Date
	/** Incremented whenever a certificate of this type is revoked */
	revision: number
}

/** The tables in the database, used to type queries made with workers-qb */
export type DatabaseSchema = {
	certificates: CertificateRecord
	krl: KrlRecord
}
