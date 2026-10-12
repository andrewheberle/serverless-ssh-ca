import { PublicKey } from "../ssh/keys.js"
import type { SshCertificate } from "../ssh/certificate.js"
import { logger } from "../logger.js"
import type { SshCaBindings } from "../types.js"
import { D1QB } from "workers-qb"
import { z } from "zod"
import { migrateOnce } from "./migrate.js"
import { migrations } from "./migrations/index.js"
import { CertificateType, type DatabaseSchema, type KrlRecord } from "./types.js"

const connect = async (env: SshCaBindings): Promise<D1QB<DatabaseSchema>> => {
	const l = logger(env)

	try {
		l.debug("connecting to database")

		const appliedMigrations = await migrateOnce(env.DB, migrations)

		l.debug("applied database migrations", "migrations", appliedMigrations.length, "migration_names", appliedMigrations.map(m => m.name))

		return new D1QB<DatabaseSchema>(env.DB)
	} catch (err) {
		l.error("error connecting to database", "error", err)
		throw err
	}
}

// statements that increment the KRL revision, so a KRL cached for an earlier
// revision is not used again
const BumpAllRevisions = "UPDATE krl SET revision = revision + 1"

// increments the revision of the KRL for a certificate type, but only if the
// previous statement in the same batch changed a row
const BumpRevisionIfChanged = "UPDATE krl SET revision = revision + 1 WHERE certificate_type = ? AND changes() = 1"

export const dbCleanup = async (env: SshCaBindings) => {
	const l = logger(env).with("retention", env.DB_CERTIFICATE_RETENTION)

	if (env.DB_CERTIFICATE_RETENTION === "infinite") {
		l.info("skipping database cleanup")
		return
	}

	l.info("starting database cleanup")
	try {
		const qb = await connect(env)
		const res = await qb.delete({
			tableName: "certificates",
			where: {
				conditions: "unixepoch('subsec') > unixepoch(valid_before,'subsec',?)",
				params: env.DB_CERTIFICATE_RETENTION
			}
		}).execute()
		l.info("completed database cleanup", "changes", res.meta?.changes)

		// revoked certificates may have been removed from the KRLs, so cached
		// KRLs must not be used again
		if ((res.meta?.changes ?? 0) > 0) {
			await env.DB.prepare(BumpAllRevisions).run()
		}
	} catch (err) {
		l.error("error during database cleanup", "retention", env.DB_CERTIFICATE_RETENTION, "error", err)
	}
}

// the columns recorded for an issued certificate, in the order of the values
// returned by certificateValues
const CertificateColumns = ["serial", "key_id", "principals", "extensions", "valid_after", "valid_before", "certificate_type", "public_key"] as const

const certificateRecord = (certificate: SshCertificate, keyid: string, certificateType: CertificateType) => {
	// principals are recorded as distinguished names, as they were when
	// certificates were created with sshpk
	const principals = certificate.principals.map((p) => `${certificate.kind === "host" ? "CN" : "UID"}=${p}`).join(",")

	return {
		serial: `${certificate.serial}`,
		key_id: keyid,
		principals: principals,
		extensions: certificate.extensions.join(","),
		valid_after: certificate.validAfter.toISOString(),
		valid_before: certificate.validBefore.toISOString(),
		certificate_type: certificateType,
		public_key: certificate.publicKey.toString()
	}
}

const certificateValues = (certificate: SshCertificate, keyid: string, certificateType: CertificateType): (string | number)[] => {
	const record = certificateRecord(certificate, keyid, certificateType)
	return CertificateColumns.map((column) => record[column])
}

export const recordCertificate = async (env: SshCaBindings, certificate: SshCertificate, keyid: string, certificateType: CertificateType = CertificateType.User) => {
	const qb = await connect(env)
	const res = await qb.insert({
		tableName: "certificates",
		data: certificateRecord(certificate, keyid, certificateType),
	}).execute()

	if (!res.success) {
		throw new Error("error during query")
	}
}

/**
 * Records a host certificate issued by renewing another, revoking the
 * certificate that was renewed so it cannot be used or renewed again.
 *
 * This is done in a single transaction, and the renewed certificate is only
 * recorded if this call revoked the previous certificate, so when a
 * certificate is renewed more than once concurrently only one renewal is
 * recorded. A previous certificate that was never recorded (for example one
 * signed with the CA key outside of the CA) is recorded so that it can be
 * revoked.
 *
 * @param env The CA bindings
 * @param previous The certificate that was presented for renewal
 * @param certificate The certificate issued by the renewal
 * @returns true if the renewal was recorded, or false if the previous certificate was already revoked
 */
export const recordRenewal = async (env: SshCaBindings, previous: SshCertificate, certificate: SshCertificate): Promise<boolean> => {
	// ensure migrations have been applied
	await connect(env)

	const columns = CertificateColumns.join(", ")
	const placeholders = CertificateColumns.map(() => "?").join(", ")
	const revokedAt = (new Date).toISOString()

	const results = await env.DB.batch([
		env.DB.prepare(`INSERT INTO certificates (${columns}) VALUES (${placeholders}) ON CONFLICT (serial) DO NOTHING`)
			.bind(...certificateValues(previous, previous.keyId, CertificateType.Host)),
		env.DB.prepare("UPDATE certificates SET revoked_at = ? WHERE serial = ? AND certificate_type = ? AND revoked_at IS NULL")
			.bind(revokedAt, `${previous.serial}`, CertificateType.Host),
		// changes() is the number of rows revoked by the previous statement
		env.DB.prepare(`INSERT INTO certificates (${columns}) SELECT ${placeholders} WHERE changes() = 1`)
			.bind(...certificateValues(certificate, certificate.keyId, CertificateType.Host)),
		// the previous certificate was revoked if the renewed one was recorded
		env.DB.prepare(BumpRevisionIfChanged).bind(CertificateType.Host),
	])

	if (results.some((res) => !res.success)) {
		throw new Error("error during query")
	}

	return results[2]?.meta?.changes === 1
}

export const isRevoked = async (env: SshCaBindings, serial: bigint): Promise<boolean> => {
	const qb = await connect(env)
	const res = await qb.fetchOne({
		tableName: "certificates",
		fields: ["serial"],
		where: {
			conditions: "serial = ? AND revoked_at NOTNULL",
			params: `${serial}`
		},
	}).execute()

	return res.results !== undefined
}

export enum RevocationStatus {
	NotFound,
	Revoked,
	Revokable,
}

// whether a public key recorded in OpenSSH format is the same as another key,
// treating a recorded key that cannot be parsed as a different key
const isKey = (recorded: string, publicKey: PublicKey): boolean => {
	try {
		return PublicKey.parse(recorded).equals(publicKey)
	} catch {
		return false
	}
}

/**
 * Returns whether a certificate can be revoked by the holder of a public key.
 *
 * The public key is compared by fingerprint, so a key with a different
 * comment to the one the certificate was issued for still matches.
 *
 * @param env The CA bindings
 * @param serial The serial of the certificate
 * @param publicKey The public key the requester has proven possession of
 * @param certificateType The type of certificate
 * @returns The revocation status of the certificate
 */
export const revocationStatus = async (env: SshCaBindings, serial: bigint, publicKey: PublicKey, certificateType: CertificateType): Promise<RevocationStatus> => {
	const qb = await connect(env)
	const res = await qb.fetchOne({
		tableName: "certificates",
		fields: ["public_key", "revoked_at"],
		where: {
			conditions: "serial = ? AND certificate_type = ?",
			params: [`${serial}`, certificateType]
		}
	}).execute()

	// a certificate issued for another key is reported as not found, so
	// requests cannot be used to discover which serials exist
	if (res.results?.public_key == null || !isKey(res.results.public_key, publicKey)) {
		return RevocationStatus.NotFound
	}

	if (res.results.revoked_at !== null) {
		return RevocationStatus.Revoked
	}

	return RevocationStatus.Revokable
}

export const getRevocationList = async (env: SshCaBindings, certificateType: CertificateType): Promise<string[]> => {
	const qb = await connect(env)
	// fetchAll cannot infer the table from its parameters, so it is given explicitly
	// as otherwise the result is untyped once the schema has more than one table
	const res = await qb.fetchAll<"certificates", "serial">({
		tableName: "certificates",
		fields: ["serial"],
		where: {
			conditions: "revoked_at NOTNULL AND certificate_type = ? AND unixepoch('subsec') < unixepoch(valid_before,'subsec','24 hours')",
			params: certificateType
		}
	}).execute()

	if (!res.success) {
		throw new Error("error during query")
	}

	if (res.results === undefined) {
		return []
	}

	return res.results.map(item => item.serial)
}

/** The time a certificate was revoked, as an ISO 8601 string */
type RevokedCertificate = { revoked_at: string }

/**
 * Revokes a certificate that has not already been revoked.
 *
 * A certificate that is already revoked is left unchanged, so when several
 * requests revoke the same certificate concurrently only one of them revokes
 * it and the time it was first revoked is kept.
 *
 * @param env The CA bindings
 * @param serial The serial of the certificate to revoke
 * @returns The revocation time of the certificate, or an empty array if it was not revoked by this call
 */
export const revokeCertificate = async (env: SshCaBindings, serial: bigint): Promise<RevokedCertificate[]> => {
	// ensure migrations have been applied
	await connect(env)

	const revokedAt = (new Date).toISOString()

	// the KRL revision is incremented in the same transaction, so a cached KRL
	// that does not include this certificate is never used again
	const results = await env.DB.batch([
		env.DB.prepare("UPDATE certificates SET revoked_at = ? WHERE serial = ? AND revoked_at IS NULL")
			.bind(revokedAt, `${serial}`),
		env.DB.prepare("UPDATE krl SET revision = revision + 1 WHERE certificate_type = (SELECT certificate_type FROM certificates WHERE serial = ?) AND changes() = 1")
			.bind(`${serial}`),
	])

	if (results.some((res) => !res.success)) {
		throw new Error("error during query")
	}

	return results[0]?.meta?.changes === 1 ? [{ revoked_at: revokedAt }] : []
}

const KrlRevisionRow = z.object({
	revision: z.number().int().nonnegative(),
})

/**
 * Returns the revision of the KRL for a certificate type, which is
 * incremented whenever a certificate of that type is revoked.
 *
 * @param env The CA bindings
 * @param certificateType The type of certificates in the KRL
 * @returns The current revision
 */
export const getKrlRevision = async (env: SshCaBindings, certificateType: CertificateType): Promise<bigint> => {
	const qb = await connect(env)
	const res = await qb.fetchOne({
		tableName: "krl",
		fields: ["revision"],
		where: {
			conditions: "certificate_type = ?",
			params: certificateType
		}
	}).execute()

	return BigInt(KrlRevisionRow.parse(res.results).revision)
}

const KrlVersionRow = z.object({
	version: z.number().int().nonnegative(),
	digest: z.string().nullable(),
	updated_at: z.string(),
})

/**
 * Parses a timestamp from the database, which is either an ISO 8601 string or,
 * when set by SQLite's CURRENT_TIMESTAMP, "YYYY-MM-DD HH:MM:SS" in UTC.
 */
const parseTimestamp = (value: string): Date => {
	return new Date(/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$/.test(value) ? `${value.replace(" ", "T")}Z` : value)
}

/** The version of a KRL and when that version was generated */
export type KrlVersion = {
	version: bigint
	/** When the version was first generated, which is the same for every KRL with this version */
	generatedAt: Date
}

// the number of times to retry when another request updates the KRL version concurrently
const KRL_VERSION_ATTEMPTS = 5

/**
 * Get the version of the KRL for a certificate type, incrementing it if the
 * content of the KRL has changed since the version was last returned.
 *
 * The version is only ever incremented, so clients can use it to detect a
 * newer KRL. When several requests see the same change concurrently the
 * version is incremented once.
 *
 * @param env The bindings for the CA, see {@link SshCaBindings}
 * @param certificateType The type of certificates in the KRL, see {@link CertificateType}
 * @param digest A digest of the content of the KRL, which changes whenever the content does
 * @returns The version to use for the KRL, and when that version was first
 * generated so that every KRL with the version has the same generation date
 */
export const getKrlVersion = async (env: SshCaBindings, certificateType: CertificateType, digest: string): Promise<KrlVersion> => {
	const qb = await connect(env)

	for (let attempt = 0; attempt < KRL_VERSION_ATTEMPTS; attempt++) {
		const res = await qb.fetchOne({
			tableName: "krl",
			fields: ["version", "digest", "updated_at"],
			where: {
				conditions: "certificate_type = ?",
				params: certificateType
			}
		}).execute()

		const current = KrlVersionRow.parse(res.results)
		if (current.digest === digest) {
			return { version: BigInt(current.version), generatedAt: parseTimestamp(current.updated_at) }
		}

		// only update if the version has not been changed by another request,
		// recording the time to the second as that is all a KRL records
		const next = current.version + 1
		const generatedAt = new Date(Math.floor(Date.now() / 1000) * 1000)
		const updated = await qb.update<Pick<KrlRecord, "version">>({
			tableName: "krl",
			data: {
				version: next,
				digest: digest,
				updated_at: generatedAt.toISOString()
			},
			where: {
				conditions: "certificate_type = ? AND version = ?",
				params: [certificateType, current.version]
			},
			returning: ["version"]
		}).execute()

		if (!updated.success) {
			throw new Error("error during query")
		}

		if (updated.results !== undefined && updated.results.length > 0) {
			return { version: BigInt(next), generatedAt }
		}
	}

	throw new Error("unable to update KRL version due to concurrent updates")
}
