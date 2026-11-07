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
import type { ClientAddress } from "../client-address.js"

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

/** Recorded in `revoked_by` for a certificate revoked by the holder of its key */
export const KeyHolderRevoker = "key-holder"

// a certificate presented for renewal is revoked by its key holder, as
// possession of the host key is what a renewal is proven by
const RenewalRevoker = KeyHolderRevoker
const RenewalReason = "renewal"

// logs a revocation for the audit trail, however the certificate was revoked
const logRevocation = (env: StoreBindings, serial: bigint, certificateType: CertificateType, by: string, reason: string | null, address: ClientAddress | undefined): void => {
	logger(env).info("certificate revoked",
		"serial", `${serial}`,
		"certificate_type", CertificateType[certificateType].toLowerCase(),
		"revoked_by", by,
		"revocation_reason", reason,
		...(address === undefined ? [] : ["client_address", address]),
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
 * @param requestAddress The client address of the request, when known
 */
export const recordCertificate = async (env: StoreBindings, certificate: SshCertificate, keyid: string, certificateType: CertificateType = CertificateType.User, requestedBy?: string, requestAddress?: ClientAddress) => {
	const qb = await connect(env)
	const res = await qb.insert({
		tableName: "certificates",
		data: { ...certificateRecord(certificate, keyid, certificateType), requested_by: requestedBy ?? null, request_address: requestAddress ?? null },
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
 * because of the renewal, and the renewed certificate records the serial of
 * the certificate it is a renewal of without a requester, as a renewal is
 * proven by possession of the host key rather than by a requester's tokens.
 * The client address of the renewal request, when known, is recorded as both
 * the request address of the renewed certificate and the revocation address
 * of the certificate that was renewed.
 *
 * @param env The CA bindings
 * @param previous The certificate that was presented for renewal
 * @param certificate The certificate issued by the renewal
 * @param clientAddress The client address of the renewal request, when known
 * @returns true if the renewal was recorded, or false if the previous certificate was already revoked
 */
export const recordRenewal = async (env: StoreBindings, previous: SshCertificate, certificate: SshCertificate, clientAddress?: ClientAddress): Promise<boolean> => {
	// ensure migrations have been applied
	await connect(env)

	const columns = CertificateColumns.join(", ")
	const placeholders = CertificateColumns.map(() => "?").join(", ")
	const revokedAt = (new Date).toISOString()

	const results = await env.DB.batch([
		env.DB.prepare(`INSERT INTO certificates (${columns}) VALUES (${placeholders}) ON CONFLICT (serial) DO NOTHING`)
			.bind(...certificateValues(previous, previous.keyId, CertificateType.Host)),
		env.DB.prepare("UPDATE certificates SET revoked_at = ?, revoked_by = ?, revocation_reason = ?, revocation_address = ? WHERE serial = ? AND certificate_type = ? AND revoked_at IS NULL")
			.bind(revokedAt, RenewalRevoker, RenewalReason, clientAddress ?? null, `${previous.serial}`, CertificateType.Host),
		// changes() is the number of rows revoked by the previous statement
		env.DB.prepare(`INSERT INTO certificates (${columns}, renewal_of, request_address) SELECT ${placeholders}, ?, ? WHERE changes() = 1`)
			.bind(...certificateValues(certificate, certificate.keyId, CertificateType.Host), `${previous.serial}`, clientAddress ?? null),
		// the previous certificate was revoked if the renewed one was recorded
		env.DB.prepare(BumpRevisionIfChanged).bind(CertificateType.Host),
	])

	if (results.some((res) => !res.success)) {
		throw new Error("error during query")
	}

	const renewed = results[2]?.meta?.changes === 1
	if (renewed) {
		logRevocation(env, previous.serial, CertificateType.Host, RenewalRevoker, RenewalReason, clientAddress)
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
 * - `keyHolder`: the holder of the private key for `publicKey`, who has proven possession of it, may revoke a certificate issued for that key. The `clientAddress` of their request is recorded when it is known
 * - `admin`: an admin, identified by `email` exactly as the identity-aware proxy's JWT gives it, may revoke any certificate that has not expired, and must give a `reason`
 */
export type Revoker =
	| { kind: "keyHolder", publicKey: PublicKey, clientAddress?: ClientAddress | undefined }
	| { kind: "admin", email: string, reason: string }

/**
 * The result of revoking a certificate.
 *
 * - `revoked`: the certificate was revoked at `revokedAt`, an ISO 8601 string
 * - `alreadyRevoked`: the certificate was already revoked, including by another request while this one was revoking it
 * - `expired`: the certificate has expired, so an admin may not revoke it. Key holders are never refused because a certificate has expired
 * - `notFound`: there is no certificate of the type that the revoker may revoke
 */
export type RevocationResult =
	| { kind: "revoked", revokedAt: string }
	| { kind: "alreadyRevoked" }
	| { kind: "expired" }
	| { kind: "notFound" }

/** A certificate to revoke, and who is revoking it, see {@link Revoker} */
export type Revocation = {
	serial: bigint
	certificateType: CertificateType
	revoker: Revoker
}

// what is recorded in revoked_by, revocation_reason and revocation_address
// for a revoker. A key holder gives no reason, as the API does not ask for
// one, and an admin is identified by their email rather than an address
const revokedBy = (revoker: Revoker): { by: string, reason: string | null, address: ClientAddress | undefined } => {
	switch (revoker.kind) {
		case "keyHolder":
			return { by: KeyHolderRevoker, reason: null, address: revoker.clientAddress }
		case "admin":
			return { by: revoker.email, reason: revoker.reason, address: undefined }
		default: {
			const unknown: never = revoker
			throw new Error(`unknown revoker ${JSON.stringify(unknown)}`)
		}
	}
}

// whether a revoker may revoke a certificate issued for a recorded public key,
// which may not have been recorded for certificates issued by old versions
const mayRevoke = (revoker: Revoker, recordedKey: string | null): boolean => {
	switch (revoker.kind) {
		case "keyHolder":
			return recordedKey !== null && isKey(recordedKey, revoker.publicKey)
		case "admin":
			return true
		default: {
			const unknown: never = revoker
			throw new Error(`unknown revoker ${JSON.stringify(unknown)}`)
		}
	}
}

// whether a revoker is refused once a certificate has expired, which only
// admins are, as revoking an expired certificate only adds it to the KRL
const refusedWhenExpired = (revoker: Revoker): boolean => {
	switch (revoker.kind) {
		case "keyHolder":
			return false
		case "admin":
			return true
		default: {
			const unknown: never = revoker
			throw new Error(`unknown revoker ${JSON.stringify(unknown)}`)
		}
	}
}

// the state of a recorded certificate that decides whether it may be revoked,
// with whether it has expired compared in SQLite as other queries do
const RevocationStateRow = z.object({
	public_key: z.string().nullable(),
	revoked_at: z.string().nullable(),
	expired: z.union([z.literal(0), z.literal(1)]).transform((v) => v === 1),
})

const readRevocationState = async (env: StoreBindings, serial: bigint, certificateType: CertificateType): Promise<z.infer<typeof RevocationStateRow> | undefined> => {
	const res = await env.DB.prepare("SELECT public_key, revoked_at, unixepoch('subsec') >= unixepoch(valid_before,'subsec') AS expired FROM certificates WHERE serial = ? AND certificate_type = ?")
		.bind(`${serial}`, certificateType)
		.all()

	if (!res.success) {
		throw new Error("error during query")
	}

	const [row] = z.array(RevocationStateRow).max(1).parse(res.results)

	return row
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
 * be used to discover which serials exist. An admin may revoke any
 * certificate, but not once it has expired, which is checked again as it is
 * revoked so a revocation cannot race with expiry.
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
	const checkExpiry = refusedWhenExpired(revoker)

	// ensure migrations have been applied
	await connect(env)

	const state = await readRevocationState(env, serial, certificateType)
	if (state === undefined || !mayRevoke(revoker, state.public_key)) {
		return { kind: "notFound" }
	}

	if (state.revoked_at !== null) {
		return { kind: "alreadyRevoked" }
	}

	if (checkExpiry && state.expired) {
		return { kind: "expired" }
	}

	const revokedAt = (new Date).toISOString()
	const { by, reason, address } = revokedBy(revoker)

	// only the certificate the decision was made for is revoked, and only if
	// another request has not revoked it since it was read, nor (for an
	// admin) has it expired since
	const expiry = checkExpiry ? " AND unixepoch('subsec') < unixepoch(valid_before,'subsec')" : ""
	const results = await env.DB.batch([
		env.DB.prepare(`UPDATE certificates SET revoked_at = ?, revoked_by = ?, revocation_reason = ?, revocation_address = ? WHERE serial = ? AND certificate_type = ? AND public_key IS ? AND revoked_at IS NULL${expiry}`)
			.bind(revokedAt, by, reason, address ?? null, `${serial}`, certificateType, state.public_key),
		env.DB.prepare(BumpRevisionIfChanged).bind(certificateType),
	])

	if (results.some((res) => !res.success)) {
		throw new Error("error during query")
	}

	if (results[0]?.meta?.changes !== 1) {
		// another request revoked it first, or it expired in the meantime
		const now = await readRevocationState(env, serial, certificateType)
		return checkExpiry && now !== undefined && now.revoked_at === null && now.expired
			? { kind: "expired" }
			: { kind: "alreadyRevoked" }
	}

	logRevocation(env, serial, certificateType, by, reason, address)

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

/**
 * The status of a recorded certificate. A certificate that is revoked is
 * `revoked` even after it expires, an `expired` certificate is one that is
 * not revoked and whose `valid_before` has passed, and a `valid` one is
 * neither.
 */
export type CertificateStatus = "valid" | "expired" | "revoked"

// a timestamp read from the database, see parseTimestamp
const Timestamp = z.string().transform((v, ctx): Date => {
	const date = parseTimestamp(v)
	if (Number.isNaN(date.getTime())) {
		ctx.issues.push({ code: "custom", message: "must be a timestamp", input: v })
		return z.NEVER
	}

	return date
})

// a row of the certificates table as it is read back, which is validated as
// it comes from storage
const CertificateRow = z.object({
	id: z.number().int(),
	serial: z.string(),
	key_id: z.string(),
	principals: z.string(),
	extensions: z.string().nullable(),
	valid_after: Timestamp,
	valid_before: Timestamp,
	revoked_at: Timestamp.nullable(),
	certificate_type: z.enum(CertificateType),
	public_key: z.string().nullable(),
	requested_by: z.string().nullable(),
	renewal_of: z.string().nullable(),
	revoked_by: z.string().nullable(),
	revocation_reason: z.string().nullable(),
	request_address: z.string().nullable(),
	revocation_address: z.string().nullable(),
})

/** A recorded certificate as it is shown to an admin, see {@link listCertificates} and {@link getCertificate} */
export type CertificateDetails = z.infer<typeof CertificateRow>

// the columns of CertificateRow, in the order they are selected
const CertificateRowColumns = Object.keys(CertificateRow.shape).join(", ")

/**
 * Returns the status of a recorded certificate, see {@link CertificateStatus}.
 *
 * @param certificate The certificate
 * @param now The time to decide whether it has expired at
 * @returns The certificate's status
 */
export const certificateStatus = (certificate: Pick<CertificateDetails, "revoked_at" | "valid_before">, now: Date = new Date()): CertificateStatus => {
	if (certificate.revoked_at !== null) {
		return "revoked"
	}

	return certificate.valid_before.getTime() <= now.getTime() ? "expired" : "valid"
}

/** The number of certificates on each page of {@link listCertificates} */
export const CertificatePageSize = 50

/**
 * The certificates to list, see {@link listCertificates}. Filters that are
 * not set do not limit the list.
 */
export type CertificateFilter = {
	certificateType: CertificateType
	/** Only certificates with this status, or every certificate for `all` */
	status: CertificateStatus | "all"
	/** Only certificates that have this principal, matched exactly and case-sensitively against each of their principals */
	principal?: string | undefined
	/** Only certificates whose key ID contains this, compared case-insensitively */
	keyId?: string | undefined
	/** Only the certificate with this serial */
	serial?: bigint | undefined
	/** Only certificates recorded before the one with this ID, for the next page */
	before?: number | undefined
}

/** A page of certificates, see {@link listCertificates} */
export type CertificatePage = {
	certificates: CertificateDetails[]
	/** The ID to list certificates before for the next page, or undefined if this is the last page */
	next: number | undefined
}

// escapes the characters LIKE treats as patterns, and the escape character
// itself, so a value is matched literally with ESCAPE '\'
const escapeLike = (value: string): string => value.replace(/[\\%_]/g, (c) => `\\${c}`)

// the conditions on the status of a certificate, which compare valid_before
// as KRL and cleanup queries do
const statusCondition = (status: CertificateFilter["status"]): string | undefined => {
	switch (status) {
		case "all":
			return undefined
		case "revoked":
			return "revoked_at IS NOT NULL"
		case "expired":
			return "revoked_at IS NULL AND unixepoch('subsec') >= unixepoch(valid_before,'subsec')"
		case "valid":
			return "revoked_at IS NULL AND unixepoch('subsec') < unixepoch(valid_before,'subsec')"
		default: {
			const unknown: never = status
			throw new Error(`unknown certificate status ${String(unknown)}`)
		}
	}
}

/**
 * Lists recorded certificates of one type, newest first, a page of
 * {@link CertificatePageSize} at a time. Pages are found by the ID of the
 * last certificate on the previous page rather than by number, so pages
 * neither skip nor repeat certificates while others are being recorded.
 *
 * @param env The CA bindings
 * @param filter Which certificates to list, see {@link CertificateFilter}
 * @returns A page of certificates, see {@link CertificatePage}
 */
export const listCertificates = async (env: StoreBindings, filter: CertificateFilter): Promise<CertificatePage> => {
	// ensure migrations have been applied
	await connect(env)

	const conditions: string[] = ["certificate_type = ?"]
	const params: unknown[] = [filter.certificateType]

	const status = statusCondition(filter.status)
	if (status !== undefined) {
		conditions.push(status)
	}

	if (filter.principal !== undefined) {
		// principals are recorded as one comma separated string of
		// distinguished names, and cannot contain a comma themselves, so a
		// whole entry is matched by looking for it between commas. instr is
		// used rather than LIKE as it is case-sensitive
		const prefix = filter.certificateType === CertificateType.Host ? "CN" : "UID"
		conditions.push("instr(',' || principals || ',', ?) > 0")
		params.push(`,${prefix}=${filter.principal},`)
	}

	if (filter.keyId !== undefined) {
		conditions.push("lower(key_id) LIKE lower(?) ESCAPE '\\'")
		params.push(`%${escapeLike(filter.keyId)}%`)
	}

	if (filter.serial !== undefined) {
		conditions.push("serial = ?")
		params.push(`${filter.serial}`)
	}

	if (filter.before !== undefined) {
		conditions.push("id < ?")
		params.push(filter.before)
	}

	// one more than a page is read, to know whether there is a next page
	params.push(CertificatePageSize + 1)
	const res = await env.DB.prepare(`SELECT ${CertificateRowColumns} FROM certificates WHERE ${conditions.join(" AND ")} ORDER BY id DESC LIMIT ?`)
		.bind(...params)
		.all()

	if (!res.success) {
		throw new Error("error during query")
	}

	const rows = z.array(CertificateRow).parse(res.results)
	const certificates = rows.slice(0, CertificatePageSize)

	return {
		certificates,
		next: rows.length > CertificatePageSize ? certificates.at(-1)?.id : undefined,
	}
}

/**
 * Returns a recorded certificate by its serial and type.
 *
 * @param env The CA bindings
 * @param serial The serial of the certificate
 * @param certificateType The type of the certificate
 * @returns The certificate, or undefined if no certificate of that type has the serial
 */
export const getCertificate = async (env: StoreBindings, serial: bigint, certificateType: CertificateType): Promise<CertificateDetails | undefined> => {
	// ensure migrations have been applied
	await connect(env)

	const res = await env.DB.prepare(`SELECT ${CertificateRowColumns} FROM certificates WHERE serial = ? AND certificate_type = ?`)
		.bind(`${serial}`, certificateType)
		.all()

	if (!res.success) {
		throw new Error("error during query")
	}

	const [row] = z.array(CertificateRow).max(1).parse(res.results)

	return row
}

/**
 * The certificates a host certificate is linked to by renewal: the one it is
 * a renewal of, and the one that renewed it.
 */
export type RenewalLinks = {
	/** The certificate this one is a renewal of, or undefined if it is not a renewal or not known, see {@link RenewalOf} */
	renewalOf: RenewalOf | undefined
	/** The serial of the certificate that is a renewal of this one, or undefined if it was not renewed or that is not known */
	renewedAs: string | undefined
}

/**
 * The certificate a renewal renewed, which is `recorded` while it is still in
 * the database and `notRecorded` once it has been removed by
 * {@link dbCleanup}, or if it was never recorded.
 */
export type RenewalOf =
	| { kind: "recorded", serial: string }
	| { kind: "notRecorded", serial: string }

const SerialRows = z.array(z.object({ serial: z.string() })).max(1)

/**
 * Returns the certificates a certificate is linked to by renewal, see
 * {@link RenewalLinks}. Only host certificates are renewed, so a user
 * certificate has no links.
 *
 * @param env The CA bindings
 * @param certificate The certificate, see {@link getCertificate}
 * @returns The certificates it is linked to
 */
export const getRenewalLinks = async (env: StoreBindings, certificate: Pick<CertificateDetails, "serial" | "certificate_type" | "renewal_of">): Promise<RenewalLinks> => {
	if (certificate.certificate_type !== CertificateType.Host) {
		return { renewalOf: undefined, renewedAs: undefined }
	}

	// ensure migrations have been applied
	await connect(env)

	const serialOf = async (query: string, value: string): Promise<string | undefined> => {
		const res = await env.DB.prepare(query).bind(value, CertificateType.Host).all()
		if (!res.success) {
			throw new Error("error during query")
		}

		return SerialRows.parse(res.results)[0]?.serial
	}

	const renewedAs = await serialOf("SELECT serial FROM certificates WHERE renewal_of = ? AND certificate_type = ? LIMIT 1", certificate.serial)
	if (certificate.renewal_of === null) {
		return { renewalOf: undefined, renewedAs }
	}

	const previous = await serialOf("SELECT serial FROM certificates WHERE serial = ? AND certificate_type = ?", certificate.renewal_of)
	return {
		renewalOf: { kind: previous === undefined ? "notRecorded" : "recorded", serial: certificate.renewal_of },
		renewedAs,
	}
}
