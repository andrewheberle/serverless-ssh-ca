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

// decodes the base64 body of a PEM block
const decodePem = (body: string): Uint8Array<ArrayBuffer> => {
	try {
		return new Uint8Array(base64.decode(body.replace(/\s+/g, "")))
	} catch (err) {
		throw new KeyParseError("private key could not be decoded", err)
	}
}

/** The algorithms that an unencrypted PKCS#8 private key is imported as, in the order they are tried */
const Pkcs8Algorithms: readonly ({ type: "ed25519", algorithm: Algorithm } | { type: "ecdsa", curve: EcdsaCurve, algorithm: EcKeyImportParams })[] = [
	{ type: "ed25519", algorithm: { name: "Ed25519" } },
	...(["nistp256", "nistp384", "nistp521"] as const).map((curve) => ({ type: "ecdsa" as const, curve, algorithm: { name: "ECDSA", namedCurve: EcdsaCurves[curve].namedCurve } })),
]

// imports a PKCS#8 private key and exports it as a JWK, returning undefined if
// it is not a key for the algorithm. workerd imports an ECDSA key as Ed25519
// without checking its type and only fails on export, so a key is only
// accepted for an algorithm once it has also been exported.
const importPkcs8 = async (der: Uint8Array<ArrayBuffer>, algorithm: Algorithm | EcKeyImportParams | RsaHashedImportParams): Promise<JsonWebKey | undefined> => {
	try {
		const key = await crypto.subtle.importKey("pkcs8", der, algorithm, true, ["sign"])
		return await crypto.subtle.exportKey("jwk", key)
	} catch {
		return undefined
	}
}

// returns a member of a JWK exported by WebCrypto, which is always present
// for the key types that are exported
const jwkMember = (jwk: JsonWebKey, name: "d" | "x" | "y"): string => {
	const value = jwk[name]
	if (value === undefined) {
		throw new KeyParseError(`private key was missing "${name}" when exported`)
	}

	return value
}

/**
 * Parses an unencrypted Ed25519 or ECDSA private key in PKCS#8 format, as
 * created by `ssh-keygen -m PKCS8` or `openssl genpkey`
 */
const parsePkcs8PrivateKey = async (body: string): Promise<PrivateKey> => {
	const der = decodePem(body)

	for (const candidate of Pkcs8Algorithms) {
		const jwk = await importPkcs8(der, candidate.algorithm)
		if (jwk === undefined) {
			continue
		}

		const d = jwkMember(jwk, "d")
		const x = jwkMember(jwk, "x")

		if (candidate.type === "ed25519") {
			return {
				type: "ed25519",
				publicKey: new PublicKey(P.struct({ type: SSHText, key: SSHBytes }).encode({ type: "ssh-ed25519", key: base64urlnopad.decode(x) })),
				jwk: { kty: "OKP", crv: "Ed25519", d, x },
			}
		}

		const y = jwkMember(jwk, "y")
		const point = new Uint8Array([0x04, ...base64urlnopad.decode(x), ...base64urlnopad.decode(y)])

		return {
			type: "ecdsa",
			curve: candidate.curve,
			publicKey: new PublicKey(P.struct({ type: SSHText, curve: SSHText, key: SSHBytes }).encode({ type: `ecdsa-sha2-${candidate.curve}`, curve: candidate.curve, key: point })),
			jwk: { kty: "EC", crv: EcdsaCurves[candidate.curve].namedCurve, d, x, y },
		}
	}

	// RSA keys are recognised only to give a clearer error
	if (await importPkcs8(der, { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }) !== undefined) {
		throw new UnsupportedKeyError("CA key type rsa is not supported, the CA key must be Ed25519 or ECDSA")
	}

	// WebCrypto does not say why a key could not be imported, so a key of
	// another type cannot be told apart from one that is corrupt
	throw new KeyParseError("PKCS#8 private key could not be imported as an Ed25519 or ECDSA (nistp256, nistp384 or nistp521) key")
}

/**
 * Parses an unencrypted Ed25519 or ECDSA private key in OpenSSH format, as
 * created by `ssh-keygen`
 */
const parseOpenSshPrivateKey = (body: string): PrivateKey => {
	const bytes = decodePem(body)
	let container: P.UnwrapCoder<typeof OpenSshPrivateKey>
	try {
		container = OpenSshPrivateKey.decode(bytes)
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

/**
 * Parses an unencrypted Ed25519 or ECDSA private key, either in OpenSSH
 * format, as created by `ssh-keygen`, or in PKCS#8 format, as created by
 * `ssh-keygen -m PKCS8` or `openssl genpkey`
 *
 * @param text The private key, starting with `-----BEGIN OPENSSH PRIVATE KEY-----` or `-----BEGIN PRIVATE KEY-----`
 * @returns The private key. A PKCS#8 key has no comment.
 * @throws {@link KeyParseError} when the key cannot be parsed or is encrypted
 * @throws {@link UnsupportedKeyError} when the key is not an Ed25519 or ECDSA key
 */
export const parsePrivateKey = async (text: string): Promise<PrivateKey> => {
	const openssh = /-----BEGIN OPENSSH PRIVATE KEY-----([\s\S]*?)-----END OPENSSH PRIVATE KEY-----/.exec(text)
	if (openssh?.[1] !== undefined) {
		return parseOpenSshPrivateKey(openssh[1])
	}

	const pkcs8 = /-----BEGIN PRIVATE KEY-----([\s\S]*?)-----END PRIVATE KEY-----/.exec(text)
	if (pkcs8?.[1] !== undefined) {
		return parsePkcs8PrivateKey(pkcs8[1])
	}

	if (text.includes("-----BEGIN ENCRYPTED PRIVATE KEY-----")) {
		throw new KeyParseError("encrypted private keys are not supported")
	}

	throw new KeyParseError("private key was not in OpenSSH format, as created by ssh-keygen (starting with -----BEGIN OPENSSH PRIVATE KEY-----), or in PKCS#8 format (starting with -----BEGIN PRIVATE KEY-----)")
}
