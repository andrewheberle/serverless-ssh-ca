import { seconds } from "itty-time"
import sshpk from "sshpk"
import type { Certificate, Identity, Key, PrivateKey, Signature } from "sshpk"
import { SSHExtension } from "./types.js"
import { getPrivateKey, split } from "./utils.js"
import type { SshCaBindings } from "./types.js"

// sshpk is CommonJS and Node's ESM loader cannot detect most of its named exports, so values are taken from the default import
const { createCertificate, identityForHost, identityForUser, identityFromDN } = sshpk

// const sshCertificateExtensions = split(env.SSH_CERTIFICATE_EXTENSIONS)

export type CreateCertificateOptions = {
	lifetime?: number
	principals?: string[]
	extensions?: string[]
}

/* const DefaultCreateCertificateOptions: CreateCertificateOptions = {
	lifetime: seconds(env.SSH_CERTIFICATE_LIFETIME),
	principals: [],
	extensions: sshCertificateExtensions
} */

export class CertificateError extends Error {
	constructor(message: string) {
		super(message)
		this.name = "CertificateError"

		// This is necessary for proper stack trace in TypeScript
		Object.setPrototypeOf(this, CertificateError.prototype)
	}
}

/**
 * Encodes bytes as an SSH string (a uint32 length followed by the bytes)
 */
const sshString = (bytes: Buffer): Buffer => {
	const length = Buffer.alloc(4)
	length.writeUInt32BE(bytes.length)

	return Buffer.concat([length, bytes])
}

/**
 * Encodes a big-endian unsigned integer as an SSH mpint, which has no leading
 * zero bytes other than one to keep the value positive if the high bit is set
 */
const sshMpint = (bytes: Buffer): Buffer => {
	let start = 0
	while (start < bytes.length && bytes[start] === 0) {
		start++
	}
	const trimmed = bytes.subarray(start)

	return sshString(trimmed.length > 0 && trimmed[0]! & 0x80 ? Buffer.concat([Buffer.from([0]), trimmed]) : trimmed)
}

/**
 * Ensures the ECDSA signature on a certificate is written with the curve of
 * the CA key.
 *
 * sshpk works out the curve of an ECDSA signature from the length of its r
 * value, so when r has leading zero bytes (about 1 in 256 signatures for
 * nistp256 and nistp384, and about 1 in 2 for nistp521) the signature is
 * written as "ecdsa-sha2-undefined" and the certificate is rejected by
 * OpenSSH. This replaces the SSH encoding of the signature with one that uses
 * the curve of the key that made it.
 *
 * This must be called each time the certificate is signed, as signing
 * replaces the signature.
 *
 * @param certificate The signed certificate
 * @param key The CA key the certificate was signed with
 */
export const encodeEcdsaSignature = (certificate: Certificate, key: PrivateKey): void => {
	const signature: Signature | undefined = certificate.signatures.openssh?.signature
	if (key.type !== "ecdsa" || signature === undefined) {
		return
	}

	if (key.curve === undefined) {
		throw new CertificateError("ECDSA CA key has no curve")
	}

	const toBuffer = signature.toBuffer.bind(signature)
	const ssh = Buffer.concat([
		sshString(Buffer.from(`ecdsa-sha2-${key.curve}`)),
		sshString(Buffer.concat([sshMpint(signature.part.r.data), sshMpint(signature.part.s.data)])),
	])

	signature.toBuffer = (format) => format === "ssh" ? Buffer.from(ssh) : toBuffer(format)
}

export type GenerateCertificateOptions = {
	/**
	 * @internal
	 * Override the certificate serial number.
	 * Should only be set in tests.
	 */
	serial?: bigint
} & CreateCertificateOptions

export const generateCertificate = (env: SshCaBindings, email: string, key: PrivateKey, public_key: Key, options?: GenerateCertificateOptions): Certificate => {
	let { lifetime } = options ?? {}
	const { principals, extensions, serial } = options ?? {}

	// add identities
	const includeSelf = env.SSH_CERTIFICATE_INCLUDE_SELF === undefined
		? false
		: typeof env.SSH_CERTIFICATE_INCLUDE_SELF === "string"
			? env.SSH_CERTIFICATE_INCLUDE_SELF === "true"
			: env.SSH_CERTIFICATE_INCLUDE_SELF
	const identity = includeSelf
		? [identityForUser(email.split("@")[0]!)]
		: []

	// add email?
	const includeSelfEmail = env.SSH_CERTIFICATE_INCLUDE_SELF_EMAIL === undefined
		? false
		: typeof env.SSH_CERTIFICATE_INCLUDE_SELF_EMAIL === "string"
			? env.SSH_CERTIFICATE_INCLUDE_SELF_EMAIL === "true"
			: env.SSH_CERTIFICATE_INCLUDE_SELF_EMAIL
	if (includeSelfEmail) {
		identity.push(identityForUser(email))
	}

	if (principals !== undefined) {
		for (const p of principals) {
			identity.push(identityForUser(p))
		}
	}

	for (const p of split(env.SSH_CERTIFICATE_PRINCIPALS)) {
		identity.push(identityForUser(p))
	}


	// lifetime is the smaller of what was provided in the options or the default
	lifetime = lifetime !== undefined
		? Math.min(lifetime, seconds(env.SSH_CERTIFICATE_LIFETIME))
		: seconds(env.SSH_CERTIFICATE_LIFETIME)

	// generate value for serial of certificate
	const s = generateSerial(serial)

	// set issuer of certificate based on ISSUER_DN
	const issuer = identityFromDN(env.ISSUER_DN)

	// create certificate
	const certificate = createCertificate(identity, public_key, issuer, key, { lifetime: lifetime, serial: s })

	// ensure openssh info is included in certificate (should not occur)
	if (certificate.signatures.openssh === undefined) {
		throw new CertificateError("missing openssh information in certificate")
	}

	const sshCertificateExtensions = split(env.SSH_CERTIFICATE_EXTENSIONS)

	// add usage extensions
	const sshextensions: SSHExtension[] = []
	if (extensions !== undefined) {
		// if extensions are provided in request, ensure they do not include extra extensions beyond the defaults
		for (const ext of extensions) {
			if (!sshCertificateExtensions.includes(ext)) {
				throw new CertificateError(`${ext} is not allowed`)
			}

			// add to list of allowed extensions
			sshextensions.push({
				critical: false,
				name: ext,
				data: Buffer.alloc(0)
			})
		}
	} else {
		// use defaults if not provided
		sshCertificateExtensions.forEach((ext: string) => {
			sshextensions.push({
				critical: false,
				name: ext,
				data: Buffer.alloc(0)
			})
		})

	}

	// add info to certificate
	certificate.signatures = {
		openssh: {
			nonce: certificate.signatures.openssh.nonce,
			keyId: email,
			signature: certificate.signatures.openssh.signature,
			exts: sshextensions
		}
	}

	// re-sign after changes
	certificate.signWith(key)
	encodeEcdsaSignature(certificate, key)

	return certificate
}

export async function createSignedCertificate(env: SshCaBindings, email: string, public_key: Key, options?: CreateCertificateOptions): Promise<Certificate> {
	// grab private key from secret store
	const key = await getPrivateKey(env)

	if (options === undefined) {
		options = {
			lifetime: seconds(env.SSH_CERTIFICATE_LIFETIME),
			principals: [],
			extensions: split(env.SSH_CERTIFICATE_EXTENSIONS)
		}
	}

	return generateCertificate(env, email, key, public_key, options)
}

export type CreateHostCertificateOptions = {
	lifetime?: number
	principals?: string[]
	subjects?: Identity[]
}

export class BadIssuerError extends Error {
	constructor(message: string) {
		super(message)
		this.name = "BadIssuerError"

		Object.setPrototypeOf(this, BadIssuerError.prototype)
	}
}

export async function createSignedHostCertificate(env: SshCaBindings, public_key: Key, options?: CreateHostCertificateOptions): Promise<Certificate> {
	if (options === undefined) {
		options = {
			lifetime: seconds(env.SSH_HOST_CERTIFICATE_LIFETIME),
			principals: []
		}
	}
	// generate list of identities for host key
	const identity: Identity[] = []
	if (options.principals !== undefined) {
		for (const p of options.principals) {
			identity.push(identityForHost(p))
		}
	}

	// add any already provided subjects (for renewals only)
	if (options.subjects !== undefined) {
		identity.push(...options.subjects)
	}

	// grab private key from secret store
	const key = await getPrivateKey(env)

	// lifetime is the smaller of what was provided in the options or the default
	const lifetime = options.lifetime !== undefined
		? Math.min(options.lifetime, seconds(env.SSH_HOST_CERTIFICATE_LIFETIME))
		: seconds(env.SSH_HOST_CERTIFICATE_LIFETIME)

	// generate value for serial of certificate
	const serial = generateSerial()

	// set issuer of certificate based on ISSUER_DN
	const issuer = identityFromDN(env.ISSUER_DN)

	// create certificate
	const certificate = createCertificate(identity, public_key, issuer, key, { lifetime: lifetime, serial: serial })
	encodeEcdsaSignature(certificate, key)

	return certificate
}

export const generateSerial = (serial?: bigint): Buffer<ArrayBuffer> => {
	if (serial !== undefined) {
		const s = Buffer.alloc(8)
		s.writeBigUInt64BE(serial)

		return s
	}

	const randomBytes = crypto.getRandomValues(new Uint8Array(8))
	return Buffer.from(randomBytes)
}
