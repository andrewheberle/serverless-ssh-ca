import * as P from "micro-packed"
import {
	decodePublicKey,
	PublicKeyFieldCounts,
	SSHBytes,
	SSHOptions,
	SSHText,
	SSHTextList,
} from "./encoding.js"
import { base64 } from "@scure/base"
import { KeyParseError, PublicKey } from "./keys.js"
import { verify, type Signer } from "./signer.js"

/**
 * Encoding, decoding and signing of OpenSSH certificates as described in
 * PROTOCOL.certkeys from OpenSSH
 */

/** Whether a certificate is for a user or a host */
export type CertificateKind = "user" | "host"

const CertificateKinds: Readonly<Record<CertificateKind, number>> = {
	user: 1,
	host: 2,
}

/** The fields of a certificate that are set by the CA */
export type CertificateFields = {
	/** Whether the certificate is for a user or a host */
	kind: CertificateKind
	/** The public key being certified */
	publicKey: PublicKey
	/** The serial number of the certificate */
	serial: bigint
	/** The key ID of the certificate, which is logged by sshd when it is used */
	keyId: string
	/** The users or hosts the certificate is valid for */
	principals: string[]
	/** The time from which the certificate is valid, to the second */
	validAfter: Date
	/** The time until which the certificate is valid, to the second */
	validBefore: Date
	/** The names of the extensions to include, which have no data */
	extensions: string[]
}

// the fields of a certificate that follow its type, which are given the
// number of fields in the public key of the certificate
const fields = (keyFields: number) => ({
	nonce: SSHBytes,
	key: P.array(keyFields, SSHBytes),
	serial: P.U64BE,
	kind: P.U32BE,
	keyId: SSHText,
	principals: SSHTextList,
	validAfter: P.U64BE,
	validBefore: P.U64BE,
	criticalOptions: SSHOptions,
	extensions: SSHOptions,
	reserved: SSHBytes,
	signatureKey: SSHBytes,
})

const certificateType = (keyType: string): string => `${keyType}-cert-v01@openssh.com`

// a certificate without and with its signature, tagged by the certificate type
const ToBeSigned = P.tag(SSHText, Object.fromEntries(
	Object.entries(PublicKeyFieldCounts).map(([keyType, count]) => [certificateType(keyType), P.struct(fields(count))]),
))
const Certificate = P.tag(SSHText, Object.fromEntries(
	Object.entries(PublicKeyFieldCounts).map(([keyType, count]) => [certificateType(keyType), P.struct({ ...fields(count), signature: SSHBytes })]),
))

const toSeconds = (date: Date): bigint => BigInt(Math.floor(date.getTime() / 1000))

/**
 * Thrown when a certificate cannot be parsed
 */
export class CertificateParseError extends Error {
	constructor(message: string, cause?: unknown) {
		super(message)
		this.name = "CertificateParseError"
		this.cause = cause

		Object.setPrototypeOf(this, CertificateParseError.prototype)
	}
}

/**
 * A signed OpenSSH certificate
 */
export class SshCertificate {
	/** The wire encoding of the certificate */
	readonly bytes: Uint8Array
	/** The certificate type, for example "ssh-ed25519-cert-v01@openssh.com" */
	readonly type: string
	readonly kind: CertificateKind
	/** The public key being certified */
	readonly publicKey: PublicKey
	readonly serial: bigint
	readonly keyId: string
	readonly principals: string[]
	readonly validAfter: Date
	readonly validBefore: Date
	/** The names of the extensions on the certificate */
	readonly extensions: string[]
	/** The wire encoding of the public key of the CA that signed the certificate */
	readonly signatureKey: Uint8Array
	/** The signature of the CA in the SSH wire format */
	readonly signature: Uint8Array

	/**
	 * Decodes a certificate from its wire encoding. This does not verify the
	 * signature on the certificate.
	 *
	 * @param bytes The wire encoding of the certificate
	 * @throws {@link CertificateParseError} when the certificate cannot be decoded or its type is not supported
	 */
	constructor(bytes: Uint8Array) {
		let decoded: P.UnwrapCoder<typeof Certificate>
		try {
			decoded = Certificate.decode(bytes)
		} catch (err) {
			throw new CertificateParseError("certificate could not be decoded", err)
		}
		const { TAG, data } = decoded
		const kind = (Object.keys(CertificateKinds) as CertificateKind[]).find((k) => CertificateKinds[k] === data.kind)
		if (kind === undefined) {
			throw new CertificateParseError(`unknown certificate kind: ${data.kind}`)
		}

		const publicKeyType = TAG.replace(/-cert-v01@openssh\.com$/, "")
		try {
			this.publicKey = new PublicKey(P.struct({ type: SSHText, key: P.array(data.key.length, SSHBytes) }).encode({ type: publicKeyType, key: data.key }))
		} catch (err) {
			throw new CertificateParseError(err instanceof KeyParseError ? err.message : "certificate public key could not be decoded", err)
		}

		this.bytes = bytes
		this.type = TAG
		this.kind = kind
		this.serial = data.serial
		this.keyId = data.keyId
		this.principals = data.principals
		this.validAfter = new Date(Number(data.validAfter) * 1000)
		this.validBefore = new Date(Number(data.validBefore) * 1000)
		this.extensions = data.extensions.map((e) => e.name)
		this.signatureKey = data.signatureKey
		this.signature = data.signature
	}

	/**
	 * Parses a certificate in OpenSSH format, `${type} ${base64}[ ${comment}]`,
	 * as found in `-cert.pub` files. This does not verify the signature on the
	 * certificate.
	 *
	 * @param text The certificate
	 * @throws {@link CertificateParseError} when the certificate cannot be parsed or its type is not supported
	 */
	static parse(text: string): SshCertificate {
		const [type, data] = text.trim().split(/\s+/)
		if (type === undefined || type === "" || data === undefined) {
			throw new CertificateParseError("certificate was not in OpenSSH format")
		}

		let bytes: Uint8Array
		try {
			bytes = base64.decode(data)
		} catch (err) {
			throw new CertificateParseError("certificate was not valid base64", err)
		}

		const certificate = new SshCertificate(bytes)
		if (certificate.type !== type) {
			throw new CertificateParseError(`certificate type ${type} did not match encoded type ${certificate.type}`)
		}

		return certificate
	}

	/**
	 * Returns whether the certificate was signed by a CA key
	 *
	 * @param ca The public key of the CA
	 */
	async isSignedBy(ca: PublicKey): Promise<boolean> {
		if (!ca.equals(new PublicKey(this.signatureKey))) {
			return false
		}

		// the signature is the last field, so everything before it is signed
		const signed = this.bytes.subarray(0, this.bytes.length - 4 - this.signature.length)

		return await verify(ca, this.signature, new Uint8Array(signed))
	}

	/**
	 * Returns the certificate in OpenSSH format, as used for `-cert.pub` files
	 */
	toString(): string {
		return `${this.type} ${base64.encode(this.bytes)}`
	}
}

/**
 * Creates and signs an OpenSSH certificate
 *
 * @param fields The fields of the certificate
 * @param signer The CA key to sign the certificate with
 * @returns The signed certificate
 * @throws Error when the type of the public key being certified is not supported
 */
export const signCertificate = async (fields: CertificateFields, signer: Signer): Promise<SshCertificate> => {
	const { type, fields: key } = decodePublicKey(fields.publicKey.blob)

	const value = {
		nonce: crypto.getRandomValues(new Uint8Array(32)),
		key,
		serial: fields.serial,
		kind: CertificateKinds[fields.kind],
		keyId: fields.keyId,
		principals: fields.principals,
		validAfter: toSeconds(fields.validAfter),
		validBefore: toSeconds(fields.validBefore),
		criticalOptions: [],
		// options must be in lexical order and may each appear only once
		extensions: [...new Set(fields.extensions)].sort().map((name) => ({ name, data: new Uint8Array(0) })),
		reserved: new Uint8Array(0),
		signatureKey: signer.publicKey,
	}

	const tbs = ToBeSigned.encode({ TAG: certificateType(type), data: value })
	const signature = await signer.sign(new Uint8Array(tbs))

	return new SshCertificate(Certificate.encode({ TAG: certificateType(type), data: { ...value, signature } }))
}
