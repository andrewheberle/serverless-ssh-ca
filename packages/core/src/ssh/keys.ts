import { sha256 } from "@noble/hashes/sha2.js"
import { base64, base64nopad, base64urlnopad } from "@scure/base"
import * as P from "micro-packed"
import { toFixedWidth } from "../sshsig/sig_parser.js"
import { decodePublicKey, SSHBytes, SSHText } from "./encoding.js"

/**
 * Thrown when a key cannot be parsed
 */
export class KeyParseError extends Error {
	constructor(message: string, cause?: unknown) {
		super(message)
		this.name = "KeyParseError"
		this.cause = cause

		Object.setPrototypeOf(this, KeyParseError.prototype)
	}
}

/**
 * Thrown when a private key is of a type that cannot be used to sign
 */
export class UnsupportedKeyError extends Error {
	constructor(message: string) {
		super(message)
		this.name = "UnsupportedKeyError"

		Object.setPrototypeOf(this, UnsupportedKeyError.prototype)
	}
}

const equalBytes = (a: Uint8Array, b: Uint8Array): boolean => {
	return a.length === b.length && a.every((v, i) => v === b[i])
}

/**
 * An SSH public key
 */
export class PublicKey {
	/** The key type, for example "ssh-ed25519" */
	readonly type: string
	/** The wire encoding of the key (RFC 4253 section 6.6) */
	readonly blob: Uint8Array
	/** The comment of the key, if any */
	readonly comment: string | undefined

	/**
	 * @param blob The wire encoding of the key
	 * @param comment The comment of the key
	 * @throws {@link KeyParseError} when the key cannot be decoded or its type is not supported
	 */
	constructor(blob: Uint8Array, comment?: string) {
		try {
			this.type = decodePublicKey(blob).type
		} catch (err) {
			throw new KeyParseError(err instanceof Error ? err.message : "public key could not be decoded", err)
		}
		this.blob = blob
		this.comment = comment === "" ? undefined : comment
	}

	/**
	 * Parses a public key in OpenSSH format, `${type} ${base64}[ ${comment}]`
	 *
	 * @param text The public key
	 * @throws {@link KeyParseError} when the key cannot be parsed or its type is not supported
	 */
	static parse(text: string): PublicKey {
		const [type, data, ...comment] = text.trim().split(/\s+/)
		if (type === undefined || type === "" || data === undefined) {
			throw new KeyParseError("public key was not in OpenSSH format")
		}

		let blob: Uint8Array
		try {
			blob = base64.decode(data)
		} catch (err) {
			throw new KeyParseError("public key was not valid base64", err)
		}

		const key = new PublicKey(blob, comment.join(" "))
		if (key.type !== type) {
			throw new KeyParseError(`public key type ${type} did not match encoded type ${key.type}`)
		}

		return key
	}

	/**
	 * Returns the SHA256 fingerprint of the key, as shown by `ssh-keygen -l`,
	 * for example "SHA256:79mq0wtpQMTvS4+Of8VzLN0qmYWNUyTXYmqKwhEgSLs"
	 */
	fingerprint(): string {
		return `SHA256:${base64nopad.encode(sha256(this.blob))}`
	}

	/**
	 * Returns whether this is the same key as another, ignoring comments
	 */
	equals(other: PublicKey): boolean {
		return equalBytes(this.blob, other.blob)
	}

	/**
	 * Returns a copy of the key with a different comment
	 */
	withComment(comment: string | undefined): PublicKey {
		return new PublicKey(this.blob, comment)
	}

	/**
	 * Returns the key in OpenSSH format, `${type} ${base64}[ ${comment}]`
	 */
	toString(): string {
		const key = `${this.type} ${base64.encode(this.blob)}`

		return this.comment === undefined ? key : `${key} ${this.comment}`
	}
}

/**
 * The smallest RSA key, in bits, that the CA will issue a certificate for.
 * This matches the minimum accepted by ssh-ca-client.
 */
export const MinimumRsaKeyBits = 2048

/**
 * Returns the size in bits of the modulus of an RSA public key, or undefined
 * if the key is not an RSA key.
 *
 * @param key The public key
 */
export const rsaKeyBits = (key: PublicKey): number | undefined => {
	if (key.type !== "ssh-rsa") {
		return undefined
	}

	// the fields of an RSA key are the exponent and the modulus, an mpint
	// that may have a leading zero byte to keep it positive
	const modulus = decodePublicKey(key.blob).fields[1]
	if (modulus === undefined) {
		return undefined
	}

	const start = modulus.findIndex((byte) => byte !== 0)
	const first = modulus[start]
	if (start === -1 || first === undefined) {
		return 0
	}

	return (modulus.length - start - 1) * 8 + first.toString(2).length
}

/** The ECDSA curves that can be used to sign */
export type EcdsaCurve = "nistp256" | "nistp384" | "nistp521"

const EcdsaCurves: Readonly<Record<EcdsaCurve, { namedCurve: string, size: number }>> = {
	nistp256: { namedCurve: "P-256", size: 32 },
	nistp384: { namedCurve: "P-384", size: 48 },
	nistp521: { namedCurve: "P-521", size: 66 },
}

/**
 * A private key that can be used to sign, with its key material as a JWK for
 * WebCrypto
 */
export type PrivateKey = {
	readonly type: "ed25519"
	readonly publicKey: PublicKey
	readonly jwk: JsonWebKey
} | {
	readonly type: "ecdsa"
	readonly curve: EcdsaCurve
	readonly publicKey: PublicKey
	readonly jwk: JsonWebKey
}

// "openssh-key-v1\0"
const AUTH_MAGIC = new TextEncoder().encode("openssh-key-v1\0")

/** The container of an OpenSSH private key (PROTOCOL.key) */
const OpenSshPrivateKey = P.struct({
	magic: P.magicBytes(AUTH_MAGIC),
	cipherName: SSHText,
	kdfName: SSHText,
	kdfOptions: SSHBytes,
	publicKeys: P.array(P.U32BE, SSHBytes),
	privateKeys: SSHBytes,
})

/** The start of the (decrypted) private section of an OpenSSH private key */
const PrivateSectionStart = P.struct({
	check1: P.U32BE,
	check2: P.U32BE,
	type: SSHText,
})

const Ed25519PrivateKey = P.struct({
	check1: P.U32BE,
	check2: P.U32BE,
	type: SSHText,
	publicKey: SSHBytes,
	// the seed followed by the public key
	privateKey: SSHBytes,
	comment: SSHText,
})

const EcdsaPrivateKey = P.struct({
	check1: P.U32BE,
	check2: P.U32BE,
	type: SSHText,
	curve: SSHText,
	publicKey: SSHBytes,
	// an mpint
	privateKey: SSHBytes,
	comment: SSHText,
})

/**
 * Returns a short name for the type of a key, for example "rsa" for "ssh-rsa"
 */
const keyTypeName = (type: string): string => {
	return type.replace(/^ssh-/, "").replace(/^ecdsa-sha2-.*$/, "ecdsa")
}

/**
 * Parses an unencrypted Ed25519 or ECDSA private key in OpenSSH format, as
 * created by `ssh-keygen`
 *
 * @param text The private key, starting with `-----BEGIN OPENSSH PRIVATE KEY-----`
 * @returns The private key
 * @throws {@link KeyParseError} when the key cannot be parsed or is encrypted
 * @throws {@link UnsupportedKeyError} when the key is not an Ed25519 or ECDSA key
 */
export const parsePrivateKey = (text: string): PrivateKey => {
	const match = /-----BEGIN OPENSSH PRIVATE KEY-----([\s\S]*?)-----END OPENSSH PRIVATE KEY-----/.exec(text)
	if (match === null) {
		throw new KeyParseError("private key was not in OpenSSH format, as created by ssh-keygen (starting with -----BEGIN OPENSSH PRIVATE KEY-----)")
	}

	let container: P.UnwrapCoder<typeof OpenSshPrivateKey>
	try {
		container = OpenSshPrivateKey.decode(base64.decode(match[1]!.replace(/\s+/g, "")))
	} catch (err) {
		throw new KeyParseError("private key could not be decoded", err)
	}

	if (container.cipherName !== "none" || container.kdfName !== "none") {
		throw new KeyParseError("encrypted private keys are not supported")
	}
	if (container.publicKeys.length !== 1) {
		throw new KeyParseError(`private key must contain one key, not ${container.publicKeys.length}`)
	}

	// the private section is padded to a block size, so may have trailing bytes
	const options = { allowUnreadBytes: true }
	let start: P.UnwrapCoder<typeof PrivateSectionStart>
	try {
		start = PrivateSectionStart.decode(container.privateKeys, options)
	} catch (err) {
		throw new KeyParseError("private key could not be decoded", err)
	}
	if (start.check1 !== start.check2) {
		throw new KeyParseError("private key check values did not match")
	}

	try {
		if (start.type === "ssh-ed25519") {
			const key = Ed25519PrivateKey.decode(container.privateKeys, options)
			if (key.publicKey.length !== 32 || key.privateKey.length !== 64) {
				throw new KeyParseError("Ed25519 private key was an unexpected length")
			}
			const publicKey = new PublicKey(container.publicKeys[0]!, key.comment)
			if (!equalBytes(P.struct({ type: SSHText, key: SSHBytes }).encode({ type: start.type, key: key.publicKey }), publicKey.blob)) {
				throw new KeyParseError("private key did not match its public key")
			}

			return {
				type: "ed25519",
				publicKey,
				jwk: {
					kty: "OKP",
					crv: "Ed25519",
					d: base64urlnopad.encode(key.privateKey.subarray(0, 32)),
					x: base64urlnopad.encode(key.publicKey),
				},
			}
		}

		if (start.type.startsWith("ecdsa-sha2-")) {
			const key = EcdsaPrivateKey.decode(container.privateKeys, options)
			const curve = EcdsaCurves[key.curve as EcdsaCurve]
			if (curve === undefined || start.type !== `ecdsa-sha2-${key.curve}`) {
				throw new UnsupportedKeyError(`ECDSA curve ${key.curve} is not supported`)
			}
			if (key.publicKey.length !== 1 + curve.size * 2 || key.publicKey[0] !== 0x04) {
				throw new KeyParseError(`unexpected ECDSA public key encoding for ${key.curve}`)
			}
			const publicKey = new PublicKey(container.publicKeys[0]!, key.comment)
			if (!equalBytes(P.struct({ type: SSHText, curve: SSHText, key: SSHBytes }).encode({ type: start.type, curve: key.curve, key: key.publicKey }), publicKey.blob)) {
				throw new KeyParseError("private key did not match its public key")
			}

			return {
				type: "ecdsa",
				curve: key.curve as EcdsaCurve,
				publicKey,
				jwk: {
					kty: "EC",
					crv: curve.namedCurve,
					// d is an mpint, so may be short or have a leading sign byte
					d: base64urlnopad.encode(toFixedWidth(key.privateKey, curve.size)),
					x: base64urlnopad.encode(key.publicKey.subarray(1, 1 + curve.size)),
					y: base64urlnopad.encode(key.publicKey.subarray(1 + curve.size)),
				},
			}
		}
	} catch (err) {
		if (err instanceof KeyParseError || err instanceof UnsupportedKeyError) {
			throw err
		}
		throw new KeyParseError("private key could not be decoded", err)
	}

	throw new UnsupportedKeyError(`CA key type ${keyTypeName(start.type)} is not supported, the CA key must be Ed25519 or ECDSA`)
}

