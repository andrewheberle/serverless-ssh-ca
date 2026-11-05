import { PublicKey } from "../ssh/keys.js"
import type { SshCertificate } from "../ssh/certificate.js"
import { logger } from "../logger.js"
import type { SshCaBindings } from "../types.js"
import { caConfig } from "../config.js"
import { D1QB } from "workers-qb"
import { z } from "zod"
import { migrateOnce } from "./migrate.js"
import { migrations } from "./migrations/index.js"
import { CertificateType, type DatabaseSchema, type KrlRecord } from "./types.js"

/**
 * The bindings used to read and record certificates.
 */
export type StoreBindings = Pick<SshCaBindings, "DB" | "LOG_LEVEL">

const connect = async (env: StoreBindings): Promise<D1QB<DatabaseSchema>> => {
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

// recorded in revoked_by for a certificate revoked by the holder of its key
const KeyHolderRevoker = "key-holder"

// a certificate presented for renewal is revoked by its key holder, as
// possession of the host key is what a renewal is proven by
const RenewalRevoker = KeyHolderRevoker
const RenewalReason = "renewal"

// logs a revocation for the audit trail, however the certificate was revoked
const logRevocation = (env: StoreBindings, serial: bigint, certificateType: CertificateType, by: string, reason: string | null): void => {
	logger(env).info("certificate revoked",
		"serial", `${serial}`,
		"certificate_type", CertificateType[certificateType].toLowerCase(),
		"revoked_by", by,
		"revocation_reason", reason,
	)
}

// how long a revoked certificate is kept in the KRL after it expires, see
// getRevocationList, as an SQLite date modifier
const KrlGracePeriod = "24 hours"

/**
 * Removes certificates that expired longer ago than the retention period in
 * `DB_CERTIFICATE_RETENTION`.
 *
 * A revoked certificate is never removed while it is still in a KRL, which is
 * until 24 hours after it expires, whatever the retention. A
 * certificate removed before then would drop out of the KRL while it is still
 * valid, and could be renewed again if it is a host certificate.
 *
 * @param env The CA bindings
 */
export const dbCleanup = async (env: SshCaBindings): Promise<void> => {
	const { retention } = caConfig(env)
	const l = logger(env).with("retention", env.DB_CERTIFICATE_RETENTION)

	switch (retention.kind) {
		case "infinite":
			l.info("skipping database cleanup")
			return
		case "period":
			break
		default: {
			const unknown: never = retention
			throw new Error(`unknown retention ${JSON.stringify(unknown)}`)
		}
	}

	l.info("starting database cleanup")
	try {
		const qb = await connect(env)
		const res = await qb.delete({
			tableName: "certificates",
			where: {
				conditions: [
					"unixepoch('subsec') > unixepoch(valid_before,'subsec',?)",
					"(revoked_at IS NULL OR unixepoch('subsec') >= unixepoch(valid_before,'subsec',?))",
				],
				params: [retention.modifier, KrlGracePeriod],
			}
		}).execute()
		l.info("completed database cleanup", "changes", res.meta?.changes)

		// revoked certificates may have been removed from the KRLs, so cached
		// KRLs must not be used again
		if ((res.meta?.changes ?? 0) > 0) {
			await env.DB.prepare(BumpAllRevisions).run()
		}
	} catch (err) {
		l.error("error during database cleanup", "error", err)
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

/**
 * Records an issued certificate, so it can be revoked and listed.
 *
 * @param env The CA bindings
 * @param certificate The certificate that was issued
 * @param keyid The key ID of the certificate
 * @param certificateType The type of certificate
 * @param requestedBy The email address of the requester who asked for the certificate, when known
 */
export const recordCertificate = async (env: StoreBindings, certificate: SshCertificate, keyid: string, certificateType: CertificateType = CertificateType.User, requestedBy?: string) => {
	const qb = await connect(env)
	const res = await qb.insert({
		tableName: "certificates",
		data: { ...certificateRecord(certificate, keyid, certificateType), requested_by: requestedBy ?? null },
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
 * The certificate that was renewed is recorded as revoked by its key holder
 * because of the renewal, and the renewed certificate keeps the requester of
 * the certificate that was renewed, as a renewal is proven by possession of
 * the host key rather than by a requester's tokens.
 *
 * @param env The CA bindings
 * @param previous The certificate that was presented for renewal
 * @param certificate The certificate issued by the renewal
 * @returns true if the renewal was recorded, or false if the previous certificate was already revoked
 */
export const recordRenewal = async (env: StoreBindings, previous: SshCertificate, certificate: SshCertificate): Promise<boolean> => {
	// ensure migrations have been applied
	await connect(env)

	const columns = CertificateColumns.join(", ")
	const placeholders = CertificateColumns.map(() => "?").join(", ")
	const revokedAt = (new Date).toISOString()

	const results = await env.DB.batch([
		env.DB.prepare(`INSERT INTO certificates (${columns}) VALUES (${placeholders}) ON CONFLICT (serial) DO NOTHING`)
			.bind(...certificateValues(previous, previous.keyId, CertificateType.Host)),
		env.DB.prepare("UPDATE certificates SET revoked_at = ?, revoked_by = ?, revocation_reason = ? WHERE serial = ? AND certificate_type = ? AND revoked_at IS NULL")
			.bind(revokedAt, RenewalRevoker, RenewalReason, `${previous.serial}`, CertificateType.Host),
		// changes() is the number of rows revoked by the previous statement
		env.DB.prepare(`INSERT INTO certificates (${columns}, requested_by) SELECT ${placeholders}, (SELECT requested_by FROM certificates WHERE serial = ?) WHERE changes() = 1`)
			.bind(...certificateValues(certificate, certificate.keyId, CertificateType.Host), `${previous.serial}`),
		// the previous certificate was revoked if the renewed one was recorded
		env.DB.prepare(BumpRevisionIfChanged).bind(CertificateType.Host),
	])

	if (results.some((res) => !res.success)) {
		throw new Error("error during query")
	}

	const renewed = results[2]?.meta?.changes === 1
	if (renewed) {
		logRevocation(env, previous.serial, CertificateType.Host, RenewalRevoker, RenewalReason)
	}

	return renewed
}

export const isRevoked = async (env: StoreBindings, serial: bigint): Promise<boolean> => {
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

// whether a public key recorded in OpenSSH format is the same as another key,
// treating a recorded key that cannot be parsed as a different key
const isKey = (recorded: string, publicKey: PublicKey): boolean => {
	try {
		return PublicKey.parse(recorded).equals(publicKey)
	} catch {
		return false
	}
}

export const getRevocationList = async (env: SshCaBindings, certificateType: CertificateType): Promise<string[]> => {
	const qb = await connect(env)
	// fetchAll cannot infer the table from its parameters, so it is given explicitly
	// as otherwise the result is untyped once the schema has more than one table
	const res = await qb.fetchAll<"certificates", "serial">({
		tableName: "certificates",
		fields: ["serial"],
		where: {
			conditions: "revoked_at NOTNULL AND certificate_type = ? AND unixepoch('subsec') < unixepoch(valid_before,'subsec',?)",
			params: [certificateType, KrlGracePeriod]
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

/**
 * Who is revoking a certificate, which decides whether they may.
 *
 * - `keyHolder`: the holder of the private key for `publicKey`, who has proven possession of it, may revoke a certificate issued for that key
 */
export type Revoker =
	| { kind: "keyHolder", publicKey: PublicKey }

/**
 * The result of revoking a certificate.
 *
 * - `revoked`: the certificate was revoked at `revokedAt`, an ISO 8601 string
 * - `alreadyRevoked`: the certificate was already revoked, including by another request while this one was revoking it
 * - `notFound`: there is no certificate of the type that the revoker may revoke
 */
export type RevocationResult =
	| { kind: "revoked", revokedAt: string }
	| { kind: "alreadyRevoked" }
	| { kind: "notFound" }

/** A certificate to revoke, and who is revoking it, see {@link Revoker} */
export type Revocation = {
	serial: bigint
	certificateType: CertificateType
	revoker: Revoker
}

// what is recorded in revoked_by for a revoker
const revokedBy = (revoker: Revoker): string => {
	switch (revoker.kind) {
		case "keyHolder":
			return KeyHolderRevoker
		default: {
			const unknown: never = revoker.kind
			throw new Error(`unknown revoker ${String(unknown)}`)
		}
	}
}

// whether a revoker may revoke a certificate issued for a recorded public key
const mayRevoke = (revoker: Revoker, recordedKey: string): boolean => {
	switch (revoker.kind) {
		case "keyHolder":
			return isKey(recordedKey, revoker.publicKey)
		default: {
			const unknown: never = revoker.kind
			throw new Error(`unknown revoker ${String(unknown)}`)
		}
	}
}

/**
 * Revokes a certificate if the revoker may revoke it, see {@link Revoker}.
 *
 * Whether the revoker may revoke the certificate is decided from the recorded
 * certificate, and the certificate is only revoked if that record is
 * unchanged, so a decision is never applied to a different certificate. A key
 * holder's key is compared by fingerprint, so a key with a different comment
 * to the one the certificate was issued for still matches, and a certificate
 * issued for another key is reported as not found so that revocations cannot
 * be used to discover which serials exist.
 *
 * A certificate is only revoked once, so when several requests revoke the
 * same certificate concurrently one of them revokes it and the time it was
 * first revoked is kept. The KRL revision for the certificate type is
 * incremented in the same transaction, so a cached KRL that does not include
 * the certificate is never used again.
 *
 * @param env The CA bindings
 * @param revocation The certificate to revoke and who is revoking it, see {@link Revocation}
 * @returns Whether the certificate was revoked, see {@link RevocationResult}
 */
export const revokeCertificate = async (env: SshCaBindings, revocation: Revocation): Promise<RevocationResult> => {
	const { serial, certificateType, revoker } = revocation

	const qb = await connect(env)
	const res = await qb.fetchOne({
		tableName: "certificates",
		fields: ["public_key", "revoked_at"],
		where: {
			conditions: "serial = ? AND certificate_type = ?",
			params: [`${serial}`, certificateType]
		}
	}).execute()

	const recordedKey = res.results?.public_key
	if (recordedKey == null || !mayRevoke(revoker, recordedKey)) {
		return { kind: "notFound" }
	}

	if (res.results?.revoked_at != null) {
		return { kind: "alreadyRevoked" }
	}

	const revokedAt = (new Date).toISOString()
	const by = revokedBy(revoker)

	// only the certificate the decision was made for is revoked, and only if
	// another request has not revoked it since it was read. No reason is
	// recorded, as the API does not ask for one
	const results = await env.DB.batch([
		env.DB.prepare("UPDATE certificates SET revoked_at = ?, revoked_by = ?, revocation_reason = NULL WHERE serial = ? AND certificate_type = ? AND public_key = ? AND revoked_at IS NULL")
			.bind(revokedAt, by, `${serial}`, certificateType, recordedKey),
		env.DB.prepare(BumpRevisionIfChanged).bind(certificateType),
	])

	if (results.some((res) => !res.success)) {
		throw new Error("error during query")
	}

	if (results[0]?.meta?.changes !== 1) {
		return { kind: "alreadyRevoked" }
	}

	logRevocation(env, serial, certificateType, by, null)

	return { kind: "revoked", revokedAt }
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
