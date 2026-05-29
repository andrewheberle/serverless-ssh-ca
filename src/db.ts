import { tryWhile } from "@cloudflare/actors"
import { Certificate, Format, Identity } from "sshpk"
import { logger } from "./logger"
import type { SshCaBindings } from "./types"

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

export const runStatement = async <T = Record<string, unknown>>(stmt: D1PreparedStatement) => {
	return await tryWhile(async () => {
		return await stmt.run<T>();
	}, shouldRetry);
}

export const shouldRetry = (err: unknown, nextAttempt: number) => {
	const errMsg = String(err);
	const isRetryableError =
		errMsg.includes("Network connection lost") ||
		errMsg.includes("storage caused object to be reset") ||
		errMsg.includes("reset because its code was updated") ||
		errMsg.includes("stream because client disconnected")

	if (nextAttempt <= 5 && isRetryableError) {
		return true
	}

	return false
}

export const dbCleanup = async (env: SshCaBindings) => {
	const l = logger(env).with("retention", env.DB_CERTIFICATE_RETENTION)

	if (env.DB_CERTIFICATE_RETENTION === "infinite") {
		l.info("skipping database cleanup")
	}

	l.info("starting database cleanup")
	try {
		const stmt = env.DB.prepare("DELETE FROM certificates WHERE unixepoch('subsec') > unixepoch(valid_before,'subsec',?)")
			.bind(env.DB_CERTIFICATE_RETENTION)
		const res = await stmt.run()
		l.info("completed database cleanup", "changes", res.meta.changes)
	} catch (err) {
		l.error("error during database cleanup", "retention", env.DB_CERTIFICATE_RETENTION)
	}
}

export const recordCertificate = async (env: SshCaBindings, certificate: Certificate, keyid: string, certificateType: CertificateType = CertificateType.User) => {
	const serial = certificate.serial.readBigUInt64BE(0)
	const subjects = certificate.subjects.map((v: Identity): string => {
		return v.toString()
	}).join(",")
	const extensions = certificate.getExtensions().map((v: Format.OpenSshSignatureExt | Format.x509SignatureExt): string => {
		// @ts-ignore: the name property does exist
		return v.name as string
	}).join(",")
	const stmt = env.DB
		.prepare("INSERT INTO certificates (serial, key_id, principals, extensions, valid_after, valid_before, certificate_type, public_key) VALUES (?, ?, ?, ?, ?, ?, ?, ?)")
		.bind(`${serial}`, keyid, subjects, extensions, certificate.validFrom.toISOString(), certificate.validUntil.toISOString(), certificateType, certificate.subjectKey.toString("ssh"))
	const res = await runStatement(stmt)

	if (!res.success) {
		if (res.error !== undefined) {
			throw new Error(res.error)
		}

		throw new Error("error during query")
	}
}

export const isRevoked = async (env: SshCaBindings, serial: bigint): Promise<boolean> => {
	const stmt = env.DB
		.prepare("SELECT serial FROM certificates WHERE serial = ? AND revoked_at NOTNULL")
		.bind(`${serial}`)
	const res = await runStatement(stmt)

	return res.results.length > 0
}

export enum RevocationStatus {
	NotFound,
	Revoked,
	Revokable,
	Unrevokable
}

export const revocationStatus = async (env: SshCaBindings, serial: bigint, publickey: string, certificateType: CertificateType): Promise<RevocationStatus> => {
	const stmt = env.DB
		.prepare("SELECT public_key, revoked_at as count FROM certificates WHERE serial = ? AND public_key = ? AND certificate_type = ?")
		.bind(`${serial}`, publickey, certificateType)
	const res = await runStatement<{ public_key: string, revoked_at: string | null }>(stmt)

	if (res.results.length === 0) {
		return RevocationStatus.NotFound
	}

	const row = res.results?.[0]
	if (!row) {
		return RevocationStatus.NotFound
	}

	if (row.revoked_at !== null) {
		return RevocationStatus.Revoked
	}

	if (publickey === row.public_key) {
		return RevocationStatus.Revokable
	}

	return RevocationStatus.Unrevokable
}

export const getRevocationList = async (env: SshCaBindings, certificateType: CertificateType): Promise<string[]> => {
	const stmt = env.DB
		.prepare("SELECT serial FROM certificates WHERE revoked_at NOTNULL AND certificate_type = ? AND unixepoch('subsec') < unixepoch(valid_before,'subsec','24 hours')")
		.bind(certificateType)
	const res = await runStatement<{ serial: string }>(stmt)

	const result: string[] = []

	for (const item of res.results) {
		result.push(item.serial)
	}

	return result
}

type RevokedCertificate = {
	revoked_at: string
}

export const revokeCertificate = async (env: SshCaBindings, serial: bigint): Promise<RevokedCertificate[]> => {
	const stmt = env.DB
		.prepare("UPDATE certificates SET revoked_at = ? WHERE serial = ? RETURNING revoked_at")
		.bind((new Date).toISOString(), `${serial}`)
	const res = await runStatement<RevokedCertificate>(stmt)

	return res.results
}
