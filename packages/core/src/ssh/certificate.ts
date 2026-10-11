import * as P from "micro-packed"
import {
	decodePublicKey,
	PublicKeyFieldCounts,
	SSHBytes,
	SSHOptions,
	SSHText,
	SSHTextList,
} from "./encoding.js"
import type { Signer } from "./signer.js"

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
	/** The wire encoding of the public key being certified */
	publicKey: Uint8Array
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

const toBase64 = (bytes: Uint8Array): string => {
	let binary = ""
	for (const byte of bytes) {
		binary += String.fromCharCode(byte)
	}

	return btoa(binary)
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
	/** The wire encoding of the public key being certified */
	readonly publicKey: Uint8Array
	/** The type of the public key being certified, for example "ssh-ed25519" */
	readonly publicKeyType: string
	readonly serial: bigint
	readonly keyId: string
	readonly principals: string[]
	readonly validAfter: Date
	readonly validBefore: Date
	/** The names of the extensions on the certificate */
	readonly extensions: string[]
	/** The wire encoding of the public key of the CA that signed the certificate */
	readonly signatureKey: Uint8Array

	/**
	 * Decodes a certificate from its wire encoding. This does not verify the
	 * signature on the certificate.
	 *
	 * @param bytes The wire encoding of the certificate
	 * @throws Error when the certificate cannot be decoded or its type is not supported
	 */
	constructor(bytes: Uint8Array) {
		const { TAG, data } = Certificate.decode(bytes)
		const kind = (Object.keys(CertificateKinds) as CertificateKind[]).find((k) => CertificateKinds[k] === data.kind)
		if (kind === undefined) {
			throw new Error(`unknown certificate kind: ${data.kind}`)
		}

		this.bytes = bytes
		this.type = TAG
		this.kind = kind
		this.publicKeyType = TAG.replace(/-cert-v01@openssh\.com$/, "")
		this.publicKey = P.struct({ type: SSHText, key: P.array(data.key.length, SSHBytes) }).encode({ type: this.publicKeyType, key: data.key })
		this.serial = data.serial
		this.keyId = data.keyId
		this.principals = data.principals
		this.validAfter = new Date(Number(data.validAfter) * 1000)
		this.validBefore = new Date(Number(data.validBefore) * 1000)
		this.extensions = data.extensions.map((e) => e.name)
		this.signatureKey = data.signatureKey
	}

	/**
	 * Returns the public key being certified in OpenSSH format, without a comment
	 */
	publicKeyString(): string {
		return `${this.publicKeyType} ${toBase64(this.publicKey)}`
	}

	/**
	 * Returns the certificate in OpenSSH format, as used for `-cert.pub` files
	 */
	toString(): string {
		return `${this.type} ${toBase64(this.bytes)}`
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
	const { type, fields: key } = decodePublicKey(fields.publicKey)

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
