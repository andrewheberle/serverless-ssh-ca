import { seconds } from "itty-time"
import { Certificate, createCertificate, Identity, identityForHost, identityForUser, identityFromDN, Key, parsePrivateKey, PrivateKey } from "sshpk"
import { SSHExtension } from "./types"
import { env } from "cloudflare:workers"
import { split } from "./utils"

const sshCertificateExtensions = split(env.SSH_CERTIFICATE_EXTENSIONS)

export type CreateCertificateOptions = {
	lifetime?: number
	principals?: string[]
	extensions?: string[]
}

const DefaultCreateCertificateOptions: CreateCertificateOptions = {
	lifetime: seconds(env.SSH_CERTIFICATE_LIFETIME),
	principals: [],
	extensions: sshCertificateExtensions
}

export class CertificateError extends Error {
	constructor(message: string) {
		super(message)
		this.name = "CertificateError"

		// This is necessary for proper stack trace in TypeScript
		Object.setPrototypeOf(this, CertificateError.prototype)
	}
}

export type GenerateCertificateOptions = {
	/**
	 * @internal
	 * Override the certificate serial number.
	 * Should only be set in tests.
	 */
	serial?: bigint
} & CreateCertificateOptions

export const generateCertificate = (email: string, key: PrivateKey, public_key: Key, options?: GenerateCertificateOptions): Certificate => {
	let { lifetime, principals, extensions, serial } = options ?? {}

	// add identities
	const identity = env.SSH_CERTIFICATE_INCLUDE_SELF as string === "true"
		? [identityForUser(email.split("@")[0])]
		: []
	if (principals !== undefined) {
		for (const p of principals) {
			identity.push(identityForUser(p))
		}
	}
	if (env.SSH_CERTIFICATE_PRINCIPALS as string !== "") {
		for (const p of split(env.SSH_CERTIFICATE_PRINCIPALS)) {
			identity.push(identityForUser(p))
		}
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

	return certificate
}

export async function createSignedCertificate(email: string, public_key: Key, options: CreateCertificateOptions = DefaultCreateCertificateOptions): Promise<Certificate> {
	// grab private key from secret store
	const secret = await env.PRIVATE_KEY.get()

	// parse key
	const key = parsePrivateKey(secret)

	return generateCertificate(email, key, public_key, options)
}

export type CreateHostCertificateOptions = {
	lifetime?: number
	principals?: string[]
	subjects?: Identity[]
}

const DefaultCreateHostertificateOptions: CreateHostCertificateOptions = {
	lifetime: seconds(env.SSH_HOST_CERTIFICATE_LIFETIME),
	principals: [],
}

export class BadIssuerError extends Error {
	constructor(message: string) {
		super(message)
		this.name = "BadIssuerError"

		Object.setPrototypeOf(this, BadIssuerError.prototype)
	}
}

export async function createSignedHostCertificate(public_key: Key, options: CreateHostCertificateOptions = DefaultCreateHostertificateOptions): Promise<Certificate> {
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
	const secret = await env.PRIVATE_KEY.get()

	// parse private key
	const key = parsePrivateKey(secret)

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
