import { Logger } from "@andrewheberle/ts-slog"
import { tryWhile } from "@cloudflare/actors"
import { env } from "cloudflare:workers"
import { Certificate, Format, Identity } from "sshpk"

export enum CertificateType {
    User,
    Host
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

export const dbCleanup = async () => {
    const logger = new Logger().with("retention", env.DB_CERTIFICATE_RETENTION)

    // @ts-expect-error: This is flagged but only due to the Workers type generation
    if (env.DB_CERTIFICATE_RETENTION === "infinite") {
        logger.info("skipping database cleanup")
    }

    logger.info("starting database cleanup")
    try {
        const stmt = env.DB.prepare("DELETE FROM certificates WHERE unixepoch('subsec') > unixepoch(valid_before,'subsec',?)")
            .bind(env.DB_CERTIFICATE_RETENTION)
        const res = await stmt.run()
        logger.info("completed database cleanup", "changes", res.meta.changes)
    } catch (err) {
        logger.error("error during database cleanup", "retention", env.DB_CERTIFICATE_RETENTION)
    }
}

export const recordCertificate = async (certificate: Certificate, keyid: string, certificateType: CertificateType = CertificateType.User) => {
    const serial = certificate.serial.readBigUInt64BE(0)
    const subjects = certificate.subjects.map((v: Identity): string => {
        return v.toString()
    }).join(",")
    const extensions = certificate.getExtensions().map((v: Format.OpenSshSignatureExt | Format.x509SignatureExt): string => {
        // @ts-ignore: the name property does exist
        return v.name as string
    }).join(",")
    const stmt = env.DB
        .prepare("INSERT INTO certificates (serial, key_id, principals, extensions, valid_after, valid_before) VALUES (?, ?, ?, ?, ?, ?)")
        .bind(`${serial}`, keyid, subjects, extensions, certificate.validFrom.toISOString(), certificate.validUntil.toISOString())
    const res = await runStatement(stmt)

    if (!res.success) {
        if (res.error !== undefined) {
            throw new Error(res.error)
        }

        throw new Error("error during query")
    }
}

export const isRevoked = async (serial: bigint): Promise<boolean> => {
    const stmt = env.DB
        .prepare("SELECT serial FROM certificates WHERE serial = ? AND revoked_at NOTNULL")
        .bind(`${serial}`)
    const res = await runStatement(stmt)

    return res.results.length > 0
}

export const getRevocationList = async (certificateType: CertificateType): Promise<string[]> => {
    const stmt = env.DB
        .prepare("SELECT serial FROM certificates WHERE revoked_at NOTNULL AND certificate_type = ? AND unixepoch('subsec') < unixepoch(valid_before,'subsec','24 hours')")
        .bind(certificateType)
    const res = await runStatement<{serial: string}>(stmt)

    const result: string[] = []

    for (const item of res.results) {
        result.push(`serial: ${item.serial}`)
    }

    return result
}
