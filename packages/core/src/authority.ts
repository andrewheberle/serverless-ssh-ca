import { group, type Logger } from "@andrewheberle/ts-slog"
import { ms, seconds } from "itty-time"
import { isRevoked, recordCertificate, recordRenewal, type StoreBindings } from "./db/index.js"
import { CertificateType } from "./db/types.js"
import type { Requester } from "./requester.js"
import { signCertificate, type CertificateFields, type SshCertificate } from "./ssh/certificate.js"
import { KeyParseError, type PrivateKey, type PublicKey } from "./ssh/keys.js"
import { createSigner } from "./ssh/signer.js"
import type { SshCaBindings } from "./types.js"
import { getPrivateKey, getPublic, hostPrincipalIssue, split, subjectKeyIssue, UnsupportedKeyError } from "./utils.js"

/**
 * The bindings the Certificate Authority issues and renews certificates with.
 */
export type AuthorityConfig = StoreBindings & Pick<SshCaBindings,
	| "PRIVATE_KEY"
	| "ISSUER_DN"
	| "CERTIFICATE_REQUEST_TIME_SKEW_MAX"
	| "SSH_CERTIFICATE_EXTENSIONS"
	| "SSH_CERTIFICATE_INCLUDE_SELF"
	| "SSH_CERTIFICATE_INCLUDE_SELF_EMAIL"
	| "SSH_CERTIFICATE_LIFETIME"
	| "SSH_CERTIFICATE_PRINCIPALS"
	| "SSH_HOST_CERTIFICATE_LIFETIME"
>

/**
 * The result of issuing a certificate.
 *
 * - `issued`: the certificate was signed and recorded
 * - `notAllowed`: the CA's configuration does not allow the certificate asked for, such as one with an extension that is not permitted or without any principals
 * - `keyMisconfigured`: the CA key could not be parsed or is of a type that is not supported
 * - `storeUnavailable`: the database could not be used, so no certificate was issued
 */
export type IssueResult =
	| { kind: "issued", certificate: SshCertificate }
	| { kind: "notAllowed", message: string }
	| { kind: "keyMisconfigured", message: string }
	| { kind: "storeUnavailable", message: string }

/**
 * The result of renewing a host certificate, which is an {@link IssueResult} or
 *
 * - `notRenewable`: the certificate presented cannot be renewed, see {@link renewHostCertificate}
 * - `revokedDuringRenewal`: the certificate presented was revoked, or renewed by another request, while it was being renewed
 */
export type RenewResult =
	| IssueResult
	| { kind: "notRenewable", message: string }
	| { kind: "revokedDuringRenewal" }

/**
 * Thrown when the CA's configuration does not allow the certificate asked for.
 */
class CertificateError extends Error {
	constructor(message: string) {
		super(message)
		this.name = "CertificateError"

		Object.setPrototypeOf(this, CertificateError.prototype)
	}
}

// returns a random certificate serial number
const generateSerial = (): bigint => {
	return new DataView(crypto.getRandomValues(new Uint8Array(8)).buffer).getBigUint64(0)
}

// a boolean binding, which may be set as a string
const flag = (value: string | boolean | undefined): boolean => {
	return typeof value === "string" ? value === "true" : value ?? false
}

// the smaller of a requested lifetime and the maximum, or the maximum when
// none was requested
const clampLifetime = (requested: number | undefined, maximum: number): number => {
	return requested === undefined ? maximum : Math.min(requested, maximum)
}

// signs a certificate valid from the current second for its lifetime in seconds
const sign = async (key: PrivateKey, fields: Omit<CertificateFields, "validAfter" | "validBefore">, lifetime: number): Promise<SshCertificate> => {
	// OpenSSH accepts a certificate without principals for any user or host
	if (fields.principals.length === 0) {
		throw new CertificateError("a certificate must have at least one principal")
	}

	// the validity is to the second, so starts at the current second rather
	// than in the future
	const validAfter = new Date(Math.floor(Date.now() / 1000) * 1000)
	const validBefore = new Date(validAfter.getTime() + lifetime * 1000)

	return await signCertificate({ ...fields, validAfter, validBefore }, await createSigner(key))
}

type KeyResult =
	| { kind: "loaded", key: PrivateKey }
	| { kind: "keyMisconfigured", message: string }

const loadKey = async (config: AuthorityConfig, l: Logger): Promise<KeyResult> => {
	try {
		return { kind: "loaded", key: await getPrivateKey(config) }
	} catch (err) {
		switch (true) {
			case (err instanceof UnsupportedKeyError):
				l.error(err.message)
				return { kind: "keyMisconfigured", message: err.message }
			case (err instanceof KeyParseError):
				// the reason is only logged, as it may describe the key
				l.error(`error parsing private key: ${err.message}`, "error", err)
				return { kind: "keyMisconfigured", message: "error parsing private key" }
			default:
				throw err
		}
	}
}

type SignResult =
	| { kind: "signed", certificate: SshCertificate }
	| { kind: "notAllowed", message: string }

// signs a certificate, unless the CA's configuration does not allow it
const trySign = async (l: Logger, signed: () => Promise<SshCertificate>): Promise<SignResult> => {
	try {
		return { kind: "signed", certificate: await signed() }
	} catch (err) {
		if (err instanceof CertificateError) {
			l.warn("certificate could not be issued", "error", err.message)
			return { kind: "notAllowed", message: err.message }
		}
		throw err
	}
}

type StoreResult<T> =
	| { kind: "stored", value: T }
	| { kind: "storeUnavailable", message: string }

// uses the database, reporting when it could not be used
const tryStore = async <T>(l: Logger, use: () => Promise<T>, message: string): Promise<StoreResult<T>> => {
	try {
		return { kind: "stored", value: await use() }
	} catch (err) {
		l.error(message, "error", err)
		return { kind: "storeUnavailable", message }
	}
}

// a certificate that is not recorded cannot be revoked, so it is not issued
const RecordingProblem = "there was a problem recording the issued certificate"

const issued = (l: Logger, certificate: SshCertificate, renews?: SshCertificate): { kind: "issued", certificate: SshCertificate } => {
	l.info("completed issuing certificate",
		...group(
			"certificate", "principals",
			certificate.principals.join(","), "serial", certificate.serial,
		),
		...(renews === undefined ? [] : group("renewed", "serial", renews.serial)),
	)

	return { kind: "issued", certificate }
}

// signs and records a certificate that is not a renewal
const issue = async (config: AuthorityConfig, l: Logger, certificateType: CertificateType, signed: () => Promise<SshCertificate>): Promise<IssueResult> => {
	const result = await trySign(l, signed)
	if (result.kind !== "signed") {
		return result
	}

	const recorded = await tryStore(l, async () => await recordCertificate(config, result.certificate, result.certificate.keyId, certificateType), RecordingProblem)
	if (recorded.kind !== "stored") {
		return recorded
	}

	return issued(l, result.certificate)
}

/**
 * Issues a user certificate to a requester, valid for the principals from
 * their identity token together with those the CA adds to every user
 * certificate.
 *
 * @param config The bindings of the CA, see {@link AuthorityConfig}
 * @param requester The requester the certificate is issued to, whose email address is its key ID
 * @param publicKey The key the certificate is issued for
 * @param options The lifetime in seconds, which is no longer than `SSH_CERTIFICATE_LIFETIME`, and the extensions, which must be from `SSH_CERTIFICATE_EXTENSIONS` and are all of those when not given
 * @param l The logger for the request
 * @returns The certificate, or why it was not issued, see {@link IssueResult}
 */
export const issueUserCertificate = async (config: AuthorityConfig, requester: Requester, publicKey: PublicKey, options: { lifetime?: number, extensions?: string[] }, l: Logger): Promise<IssueResult> => {
	const key = await loadKey(config, l)
	if (key.kind !== "loaded") {
		return key
	}

	const principals = [
		...(flag(config.SSH_CERTIFICATE_INCLUDE_SELF) ? [requester.email.split("@")[0] ?? ""] : []),
		...(flag(config.SSH_CERTIFICATE_INCLUDE_SELF_EMAIL) ? [requester.email] : []),
		...requester.principals,
		...split(config.SSH_CERTIFICATE_PRINCIPALS),
	]

	return await issue(config, l, CertificateType.User, async () => {
		const allowed = split(config.SSH_CERTIFICATE_EXTENSIONS)
		const notAllowed = options.extensions?.find((extension) => !allowed.includes(extension))
		if (notAllowed !== undefined) {
			throw new CertificateError(`${notAllowed} is not allowed`)
		}

		return await sign(key.key, {
			kind: "user",
			publicKey,
			serial: generateSerial(),
			keyId: requester.email,
			principals,
			extensions: options.extensions ?? allowed,
		}, clampLifetime(options.lifetime, seconds(config.SSH_CERTIFICATE_LIFETIME)))
	})
}

// signs a host certificate, whose key ID is named after its first principal
const signHostCertificate = async (config: AuthorityConfig, key: PrivateKey, publicKey: PublicKey, principals: string[], lifetime: number | undefined): Promise<SshCertificate> => {
	return await sign(key, {
		kind: "host",
		publicKey,
		serial: generateSerial(),
		keyId: `host_${principals[0]}`,
		principals,
		extensions: [],
	}, clampLifetime(lifetime, seconds(config.SSH_HOST_CERTIFICATE_LIFETIME)))
}

/**
 * Issues a host certificate for the given principals.
 *
 * @param config The bindings of the CA, see {@link AuthorityConfig}
 * @param publicKey The key the certificate is issued for
 * @param options The principals, of which there must be at least one, and the lifetime in seconds, which is no longer than `SSH_HOST_CERTIFICATE_LIFETIME`
 * @param l The logger for the request
 * @returns The certificate, or why it was not issued, see {@link IssueResult}
 */
export const issueHostCertificate = async (config: AuthorityConfig, publicKey: PublicKey, options: { principals: string[], lifetime?: number }, l: Logger): Promise<IssueResult> => {
	const key = await loadKey(config, l)
	if (key.kind !== "loaded") {
		return key
	}

	return await issue(config, l, CertificateType.Host, async () => await signHostCertificate(config, key.key, publicKey, options.principals, options.lifetime))
}

// returns why a certificate cannot be renewed, or undefined if it can be,
// without using the database
const renewalIssue = async (config: AuthorityConfig, key: PrivateKey, certificate: SshCertificate): Promise<string | undefined> => {
	if (!await certificate.isSignedBy(await getPublic(config, key))) {
		return "the provided certificate was not signed by this CA"
	}

	// only host certificates can be renewed, as renewal does not need the
	// OIDC authentication a user certificate is issued with
	if (certificate.kind !== "host") {
		return "the provided certificate is not a host certificate"
	}

	// a certificate issued before small RSA keys were refused must not be
	// renewed, as the renewal would keep its key
	const keyIssue = subjectKeyIssue(certificate.publicKey)
	if (keyIssue !== undefined) {
		return `the provided certificate cannot be renewed: ${keyIssue}`
	}

	// a certificate issued before wildcard principals were refused must not
	// be renewed, as the renewal would keep its principals
	for (const principal of certificate.principals) {
		const principalIssue = hostPrincipalIssue(principal)
		if (principalIssue !== undefined) {
			return `the provided certificate cannot be renewed: ${principalIssue}`
		}
	}

	// the validity of a certificate issued moments ago may start up to a
	// second in the future, so clock skew is allowed for at the start
	const now = Date.now()
	if (now >= certificate.validBefore.getTime()) {
		return "the provided certificate is expired"
	}
	if (certificate.validAfter.getTime() > now + ms(config.CERTIFICATE_REQUEST_TIME_SKEW_MAX)) {
		return "the provided certificate is not yet valid"
	}

	return undefined
}

/**
 * Renews a host certificate, issuing a new certificate for the same key and
 * principals and revoking the certificate presented.
 *
 * The certificate presented must have been issued by this CA, be a host
 * certificate whose key and principals would still be allowed, be within its
 * validity period and not be revoked. These are checked in that order, so the
 * database is only used for a certificate this CA issued. Possession of the
 * key of the certificate must have been proven before it is renewed.
 *
 * @param config The bindings of the CA, see {@link AuthorityConfig}
 * @param certificate The certificate presented for renewal
 * @param options The lifetime in seconds, which is no longer than that of the certificate presented or `SSH_HOST_CERTIFICATE_LIFETIME`
 * @param l The logger for the request
 * @returns The renewed certificate, or why it was not renewed, see {@link RenewResult}
 */
export const renewHostCertificate = async (config: AuthorityConfig, certificate: SshCertificate, options: { lifetime?: number }, l: Logger): Promise<RenewResult> => {
	const key = await loadKey(config, l)
	if (key.kind !== "loaded") {
		return key
	}

	const reason = await renewalIssue(config, key.key, certificate)
	if (reason !== undefined) {
		l.warn("certificate presented for renewal cannot be renewed", "reason", reason)
		return { kind: "notRenewable", message: reason }
	}

	const revoked = await tryStore(l, async () => await isRevoked(config, certificate.serial), "there was a problem checking whether the certificate presented for renewal is revoked")
	if (revoked.kind !== "stored") {
		return revoked
	}
	if (revoked.value) {
		l.warn("certificate presented for renewal cannot be renewed", "reason", "the provided certificate is revoked")
		return { kind: "notRenewable", message: "the provided certificate is revoked" }
	}

	const originalLifetime = (certificate.validBefore.getTime() - certificate.validAfter.getTime()) / 1000
	const result = await trySign(l, async () => await signHostCertificate(config, key.key, certificate.publicKey, certificate.principals, clampLifetime(options.lifetime, originalLifetime)))
	if (result.kind !== "signed") {
		return result
	}

	// the certificate presented is revoked in the same transaction as the
	// renewal is recorded, so it is only renewed once however many requests
	// renew it at the same time
	const recorded = await tryStore(l, async () => await recordRenewal(config, certificate, result.certificate), RecordingProblem)
	if (recorded.kind !== "stored") {
		return recorded
	}
	if (!recorded.value) {
		l.warn("certificate presented for renewal was revoked before the renewal was recorded")
		return { kind: "revokedDuringRenewal" }
	}

	return issued(l, result.certificate, certificate)
}
