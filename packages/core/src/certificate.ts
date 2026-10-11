import { seconds } from "itty-time"
import type { PrivateKey, PublicKey } from "./ssh/keys.js"
import { getPrivateKey, split } from "./utils.js"
import type { SshCaBindings } from "./types.js"
import { signCertificate, type CertificateFields, type SshCertificate } from "./ssh/certificate.js"
import { createSigner } from "./ssh/signer.js"

export type CreateCertificateOptions = {
	lifetime?: number
	principals?: string[]
	extensions?: string[]
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

/**
 * Signs a certificate with the CA key
 *
 * @throws {@link CertificateError} when the certificate has no principals,
 * as OpenSSH accepts a certificate without principals for any user or host
 */
const sign = async (key: PrivateKey, fields: Omit<CertificateFields, "validAfter" | "validBefore">, lifetime: number): Promise<SshCertificate> => {
	if (fields.principals.length === 0) {
		throw new CertificateError("a certificate must have at least one principal")
	}

	// the validity is to the second, so starts at the current second rather
	// than in the future
	const validAfter = new Date(Math.floor(Date.now() / 1000) * 1000)
	const validBefore = new Date(validAfter.getTime() + lifetime * 1000)

	return await signCertificate({ ...fields, validAfter, validBefore }, await createSigner(key))
}

export const generateCertificate = async (env: SshCaBindings, email: string, key: PrivateKey, public_key: PublicKey, options?: GenerateCertificateOptions): Promise<SshCertificate> => {
	const { lifetime, principals, extensions, serial } = options ?? {}

	// add principals
	const includeSelf = env.SSH_CERTIFICATE_INCLUDE_SELF === undefined
		? false
		: typeof env.SSH_CERTIFICATE_INCLUDE_SELF === "string"
			? env.SSH_CERTIFICATE_INCLUDE_SELF === "true"
			: env.SSH_CERTIFICATE_INCLUDE_SELF
	const certificatePrincipals = includeSelf
		? [email.split("@")[0]!]
		: []

	// add email?
	const includeSelfEmail = env.SSH_CERTIFICATE_INCLUDE_SELF_EMAIL === undefined
		? false
		: typeof env.SSH_CERTIFICATE_INCLUDE_SELF_EMAIL === "string"
			? env.SSH_CERTIFICATE_INCLUDE_SELF_EMAIL === "true"
			: env.SSH_CERTIFICATE_INCLUDE_SELF_EMAIL
	if (includeSelfEmail) {
		certificatePrincipals.push(email)
	}

	if (principals !== undefined) {
		certificatePrincipals.push(...principals)
	}

	certificatePrincipals.push(...split(env.SSH_CERTIFICATE_PRINCIPALS))

	const sshCertificateExtensions = split(env.SSH_CERTIFICATE_EXTENSIONS)

	// if extensions are provided in request, ensure they do not include extra extensions beyond the defaults
	if (extensions !== undefined) {
		for (const ext of extensions) {
			if (!sshCertificateExtensions.includes(ext)) {
				throw new CertificateError(`${ext} is not allowed`)
			}
		}
	}

	// lifetime is the smaller of what was provided in the options or the default
	const certificateLifetime = lifetime !== undefined
		? Math.min(lifetime, seconds(env.SSH_CERTIFICATE_LIFETIME))
		: seconds(env.SSH_CERTIFICATE_LIFETIME)

	return await sign(key, {
		kind: "user",
		publicKey: public_key,
		serial: serial ?? generateSerial(),
		keyId: email,
		principals: certificatePrincipals,
		// use defaults if not provided
		extensions: extensions ?? sshCertificateExtensions,
	}, certificateLifetime)
}

export async function createSignedCertificate(env: SshCaBindings, email: string, public_key: PublicKey, options?: CreateCertificateOptions): Promise<SshCertificate> {
	// grab private key from secret store
	const key = await getPrivateKey(env)

	if (options === undefined) {
		options = {
			lifetime: seconds(env.SSH_CERTIFICATE_LIFETIME),
			principals: [],
			extensions: split(env.SSH_CERTIFICATE_EXTENSIONS)
		}
	}

	return await generateCertificate(env, email, key, public_key, options)
}

export type CreateHostCertificateOptions = {
	lifetime?: number
	principals?: string[]
}

export class BadIssuerError extends Error {
	constructor(message: string) {
		super(message)
		this.name = "BadIssuerError"

		Object.setPrototypeOf(this, BadIssuerError.prototype)
	}
}

export async function createSignedHostCertificate(env: SshCaBindings, public_key: PublicKey, options?: CreateHostCertificateOptions): Promise<SshCertificate> {
	const principals = options?.principals ?? []

	// grab private key from secret store
	const key = await getPrivateKey(env)

	// lifetime is the smaller of what was provided in the options or the default
	const lifetime = options?.lifetime !== undefined
		? Math.min(options.lifetime, seconds(env.SSH_HOST_CERTIFICATE_LIFETIME))
		: seconds(env.SSH_HOST_CERTIFICATE_LIFETIME)

	return await sign(key, {
		kind: "host",
		publicKey: public_key,
		serial: generateSerial(),
		keyId: `host_${principals[0]}`,
		principals,
		extensions: [],
	}, lifetime)
}

/**
 * Returns a random certificate serial number
 */
export const generateSerial = (): bigint => {
	return new DataView(crypto.getRandomValues(new Uint8Array(8)).buffer).getBigUint64(0)
}
