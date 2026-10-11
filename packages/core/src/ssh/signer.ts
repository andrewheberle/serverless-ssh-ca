import * as P from "micro-packed"
import { toFixedWidth } from "../sshsig/sig_parser.js"
import { decodePublicKey, SSHBytes, SSHText, SSHUnsignedMpint } from "./encoding.js"
import type { EcdsaCurve, PrivateKey, PublicKey } from "./keys.js"

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

const EcdsaCurves: Readonly<Record<EcdsaCurve, { namedCurve: string, hash: string, size: number }>> = {
	nistp256: { namedCurve: "P-256", hash: "SHA-256", size: 32 },
	nistp384: { namedCurve: "P-384", hash: "SHA-384", size: 48 },
	nistp521: { namedCurve: "P-521", hash: "SHA-512", size: 66 },
}

/**
 * Creates a {@link Signer} for an Ed25519 or ECDSA (P-256, P-384 or P-521)
 * private key
 *
 * @param key The private key to sign with
 * @returns The signer
 */
export const createSigner = async (key: PrivateKey): Promise<Signer> => {
	const publicKey = key.publicKey.blob

	if (key.type === "ed25519") {
		const cryptoKey = await crypto.subtle.importKey("jwk", key.jwk, { name: "Ed25519" }, false, ["sign"])

		return {
			publicKey,
			sign: async (data) => Ed25519Signature.encode({
				algorithm: "ssh-ed25519",
				signature: new Uint8Array(await crypto.subtle.sign({ name: "Ed25519" }, cryptoKey, data)),
			}),
		}
	}

	const curve = EcdsaCurves[key.curve]
	const cryptoKey = await crypto.subtle.importKey("jwk", key.jwk, { name: "ECDSA", namedCurve: curve.namedCurve }, false, ["sign"])

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

/**
 * Verifies a signature in the SSH wire format made with an Ed25519 or ECDSA
 * key
 *
 * @param publicKey The key the signature must have been made with
 * @param signature The signature in the SSH wire format
 * @param data The data that was signed
 * @returns true if the signature is valid, false if it is not or the key type is not supported
 */
export const verify = async (publicKey: PublicKey, signature: Uint8Array, data: Uint8Array<ArrayBuffer>): Promise<boolean> => {
	try {
		const { type, fields } = decodePublicKey(publicKey.blob)

		if (type === "ssh-ed25519") {
			const { algorithm, signature: raw } = Ed25519Signature.decode(signature)
			if (algorithm !== type) {
				return false
			}
			const cryptoKey = await crypto.subtle.importKey("raw", new Uint8Array(fields[0]!), { name: "Ed25519" }, false, ["verify"])

			return await crypto.subtle.verify({ name: "Ed25519" }, cryptoKey, new Uint8Array(raw), data)
		}

		const curveName = type.replace(/^ecdsa-sha2-/, "") as EcdsaCurve
		const curve = EcdsaCurves[curveName]
		if (curve !== undefined && type === `ecdsa-sha2-${curveName}`) {
			const { algorithm, signature: { r, s } } = EcdsaSignature.decode(signature)
			if (algorithm !== type || r.length > curve.size || s.length > curve.size) {
				return false
			}
			// fields are the curve name and the public point
			const cryptoKey = await crypto.subtle.importKey("raw", new Uint8Array(fields[1]!), { name: "ECDSA", namedCurve: curve.namedCurve }, false, ["verify"])
			const raw = P.utils.concatBytes(toFixedWidth(r, curve.size), toFixedWidth(s, curve.size))

			return await crypto.subtle.verify({ name: "ECDSA", hash: { name: curve.hash } }, cryptoKey, new Uint8Array(raw), data)
		}

		return false
	} catch {
		// a signature or key that cannot be decoded or imported is not valid
		return false
	}
}
