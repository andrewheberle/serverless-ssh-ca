import * as P from "micro-packed"
import type { AlgorithmPart, PrivateKey } from "sshpk"
import { toFixedWidth } from "../sshsig/sig_parser.js"
import { SSHBytes, SSHText, SSHUnsignedMpint } from "./encoding.js"

/**
 * Signs data with a CA key using WebCrypto, returning signatures in the SSH
 * wire format
 */
export interface Signer {
	/** The wire encoding of the public key of the signer */
	readonly publicKey: Uint8Array
	/**
	 * Signs data
	 *
	 * @param data The data to sign
	 * @returns The signature in the SSH wire format (RFC 4253 section 6.6)
	 */
	sign(data: Uint8Array<ArrayBuffer>): Promise<Uint8Array>
}

/** An Ed25519 signature: string algorithm, string signature */
const Ed25519Signature = P.struct({
	algorithm: SSHText,
	signature: SSHBytes,
})

/** An ECDSA signature: string algorithm, string (mpint r, mpint s) */
const EcdsaSignature = P.struct({
	algorithm: SSHText,
	signature: P.prefix(P.U32BE, P.struct({
		r: SSHUnsignedMpint,
		s: SSHUnsignedMpint,
	})),
})

type EcdsaCurve = {
	namedCurve: string
	hash: string
	// the size in bytes of each coordinate and of the private key
	size: number
}

const EcdsaCurves: Readonly<Record<string, EcdsaCurve>> = {
	nistp256: { namedCurve: "P-256", hash: "SHA-256", size: 32 },
	nistp384: { namedCurve: "P-384", hash: "SHA-384", size: 48 },
	nistp521: { namedCurve: "P-521", hash: "SHA-512", size: 66 },
}

/**
 * Returns the wire encoding of the public key of an sshpk key
 */
export const publicKeyBlob = (key: PrivateKey): Uint8Array => {
	return new Uint8Array(key.toPublic().toBuffer("rfc4253"))
}

/**
 * Get the raw bytes of a named part of an sshpk key.
 */
const keyPart = (key: PrivateKey, name: AlgorithmPart): Uint8Array => {
	const part = key.parts.find((p) => p.name === name)
	if (part === undefined) {
		throw new Error(`Missing ${name} part in ${key.type} key`)
	}

	return part.data
}

/**
 * Base64url-encode bytes without padding, as used for JWK values.
 */
const base64url = (bytes: Uint8Array): string => {
	let binary = ""
	for (const byte of bytes) {
		binary += String.fromCharCode(byte)
	}

	return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "")
}

/**
 * Creates a {@link Signer} for an Ed25519 or ECDSA (P-256, P-384 or P-521)
 * sshpk private key.
 *
 * The key is imported from its raw parts as a JWK rather than from sshpk's
 * PKCS#8 output, which drops leading zero bytes from private key values so
 * that some keys are rejected by WebCrypto.
 *
 * @param key The private key to sign with
 * @returns The signer
 * @throws Error when the key type or curve is not supported
 */
export const createSigner = async (key: PrivateKey): Promise<Signer> => {
	const publicKey = publicKeyBlob(key)

	if (key.type === "ed25519") {
		const seed = keyPart(key, "k")
		const point = keyPart(key, "A")
		if (seed.length !== 32 || point.length !== 32) {
			throw new Error(`Unexpected Ed25519 key part lengths: k=${seed.length} A=${point.length}`)
		}
		const cryptoKey = await crypto.subtle.importKey(
			"jwk",
			{ kty: "OKP", crv: "Ed25519", d: base64url(seed), x: base64url(point) },
			{ name: "Ed25519" },
			false,
			["sign"],
		)

		return {
			publicKey,
			sign: async (data) => Ed25519Signature.encode({
				algorithm: "ssh-ed25519",
				signature: new Uint8Array(await crypto.subtle.sign({ name: "Ed25519" }, cryptoKey, data)),
			}),
		}
	}

	if (key.type === "ecdsa") {
		const curve = key.curve === undefined ? undefined : EcdsaCurves[key.curve]
		if (curve === undefined) {
			throw new Error(`Unsupported ECDSA curve: ${key.curve}`)
		}

		const point = keyPart(key, "Q")
		if (point.length !== 1 + curve.size * 2 || point[0] !== 0x04) {
			throw new Error(`Unexpected ECDSA public key encoding for ${key.curve}`)
		}
		// d is an SSH mpint, so may be short or have a leading sign byte
		const d = toFixedWidth(keyPart(key, "d"), curve.size)
		const cryptoKey = await crypto.subtle.importKey(
			"jwk",
			{
				kty: "EC",
				crv: curve.namedCurve,
				d: base64url(d),
				x: base64url(point.subarray(1, 1 + curve.size)),
				y: base64url(point.subarray(1 + curve.size)),
			},
			{ name: "ECDSA", namedCurve: curve.namedCurve },
			false,
			["sign"],
		)

		return {
			publicKey,
			sign: async (data) => {
				// WebCrypto returns r || s, each the size of the curve
				const signature = new Uint8Array(await crypto.subtle.sign({ name: "ECDSA", hash: { name: curve.hash } }, cryptoKey, data))

				return EcdsaSignature.encode({
					// the algorithm is named for the curve of the key, never
					// worked out from the signature
					algorithm: `ecdsa-sha2-${key.curve}`,
					signature: {
						r: signature.subarray(0, curve.size),
						s: signature.subarray(curve.size),
					},
				})
			},
		}
	}

	throw new Error(`Unsupported key type: ${key.type}`)
}
