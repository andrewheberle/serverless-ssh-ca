import type { Certificate, Format, Identity } from "sshpk"
import { logger } from "../logger.js"
import type { SshCaBindings } from "../types.js"
import { D1QB } from "workers-qb"
import { z } from "zod"
import { migrateOnce } from "./migrate.js"
import { migrations } from "./migrations/index.js"

export enum CertificateType {
	User,
	Host
}

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

export type DatabaseSchema = {
	certificates: CertificateRecord
}

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
	} catch (err) {
		l.error("error during database cleanup", "retention", env.DB_CERTIFICATE_RETENTION, "error", err)
	}
}

export const recordCertificate = async (env: SshCaBindings, certificate: Certificate, keyid: string, certificateType: CertificateType = CertificateType.User) => {
	const serial = certificate.serial.readBigUInt64BE(0)
	const subjects = certificate.subjects.map((v: Identity): string => {
		return v.toString()
	}).join(",")
	const extensions = certificate.getExtensions().map((v: Format.OpenSshSignatureExt | Format.x509SignatureExt): string => {
		// @ts-expect-error: the name property does exist
		return v.name as string
	}).join(",")
	const qb = await connect(env)
	const res = await qb.insert({
		tableName: "certificates",
		data: {
			serial: `${serial}`,
			key_id: keyid,
			principals: subjects,
			extensions: extensions,
			valid_after: certificate.validFrom.toISOString(),
			valid_before: certificate.validUntil.toISOString(),
			certificate_type: certificateType,
			public_key: certificate.subjectKey.toString("ssh")
		},
	}).execute()

	if (!res.success) {
		throw new Error("error during query")
	}
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
	Unrevokable
}

export const revocationStatus = async (env: SshCaBindings, serial: bigint, publickey: string, certificateType: CertificateType): Promise<RevocationStatus> => {
	const qb = await connect(env)
	const res = await qb.fetchOne({
		tableName: "certificates",
		fields: ["public_key", "revoked_at"],
		where: {
			conditions: "serial = ? AND public_key = ? AND certificate_type = ?",
			params: [`${serial}`, publickey, certificateType]
		}
	}).execute()

	if (res.results === undefined) {
		return RevocationStatus.NotFound
	}

	if (res.results.revoked_at !== null) {
		return RevocationStatus.Revoked
	}

	if (publickey === res.results.public_key) {
		return RevocationStatus.Revokable
	}

	return RevocationStatus.Unrevokable
}

export const getRevocationList = async (env: SshCaBindings, certificateType: CertificateType): Promise<string[]> => {
	const qb = await connect(env)
	const res = await qb.fetchAll({
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

type RevokedCertificate = Pick<CertificateRecord, "revoked_at">

export const revokeCertificate = async (env: SshCaBindings, serial: bigint): Promise<RevokedCertificate[]> => {
	const qb = await connect(env)
	const res = await qb.update<RevokedCertificate>({
		tableName: "certificates",
		data: {
			revoked_at: (new Date).toISOString()
		},
		where: {
			conditions: "serial = ?",
			params: `${serial}`
		},
		returning: ["revoked_at"]
	}).execute()

	if (!res.success) {
		throw new Error("error during query")
	}

	if (res.results === undefined) {
		return []
	}

	return res.results
}

// the krl table is not part of DatabaseSchema as workers-qb then fails to infer
// the result types of queries on the certificates table, so rows are validated here
const KrlVersionRow = z.object({
	version: z.number().int().nonnegative(),
	digest: z.string().nullable(),
})

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
 * @returns The version to use for the KRL
 */
export const getKrlVersion = async (env: SshCaBindings, certificateType: CertificateType, digest: string): Promise<bigint> => {
	const qb = await connect(env)

	for (let attempt = 0; attempt < KRL_VERSION_ATTEMPTS; attempt++) {
		const res = await qb.fetchOne({
			tableName: "krl",
			fields: ["version", "digest"],
			where: {
				conditions: "certificate_type = ?",
				params: certificateType
			}
		}).execute()

		const current = KrlVersionRow.parse(res.results)
		if (current.digest === digest) {
			return BigInt(current.version)
		}

		// only update if the version has not been changed by another request
		const next = current.version + 1
		const updated = await qb.update({
			tableName: "krl",
			data: {
				version: next,
				digest: digest,
				updated_at: (new Date).toISOString()
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
			return BigInt(next)
		}
	}

	throw new Error("unable to update KRL version due to concurrent updates")
}
