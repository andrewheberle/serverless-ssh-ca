import * as P from "micro-packed"

/**
 * Coders for the SSH wire format (RFC 4251 section 5)
 */

/** A string of bytes, prefixed by its length as a uint32 */
export const SSHBytes = P.bytes(P.U32BE)

/** A UTF-8 string, prefixed by its length as a uint32 */
export const SSHText = P.string(P.U32BE)

/** A list of strings packed into a string, as used for certificate principals */
export const SSHTextList = P.prefix(P.U32BE, P.array(null, SSHText))

/**
 * A list of named options packed into a string, as used for certificate
 * critical options and extensions
 */
export const SSHOptions = P.prefix(P.U32BE, P.array(null, P.struct({
	name: SSHText,
	data: SSHBytes,
})))

/**
 * An mpint holding an unsigned integer, decoded to and encoded from its
 * big-endian bytes without leading zeros.
 *
 * An mpint has no leading zero bytes, other than one to keep the value
 * positive when the high bit of the first byte is set.
 */
export const SSHUnsignedMpint = P.apply(SSHBytes, {
	encode: (mpint: Uint8Array): Uint8Array => {
		let start = 0
		while (start < mpint.length && mpint[start] === 0) {
			start++
		}

		return mpint.subarray(start)
	},
	decode: (value: Uint8Array): Uint8Array => {
		let start = 0
		while (start < value.length && value[start] === 0) {
			start++
		}
		const trimmed = value.subarray(start)

		return trimmed.length > 0 && trimmed[0]! & 0x80
			? P.utils.concatBytes(new Uint8Array([0]), trimmed)
			: trimmed
	},
})

/** The number of fields that follow the type in the wire encoding of a public key of each type */
export const PublicKeyFieldCounts: Readonly<Record<string, number>> = {
	"ssh-ed25519": 1, // public key
	"ecdsa-sha2-nistp256": 2, // curve, public key
	"ecdsa-sha2-nistp384": 2,
	"ecdsa-sha2-nistp521": 2,
	"ssh-rsa": 2, // e, n
}

/**
 * Splits the wire encoding of a public key into its type and the encoded
 * fields that follow it
 *
 * @param blob The wire encoding of the public key
 * @returns The key type and its fields
 * @throws Error when the key type is not supported or the encoding is invalid
 */
export const decodePublicKey = (blob: Uint8Array): { type: string, fields: Uint8Array[] } => {
	const type = SSHText.decode(blob, { allowUnreadBytes: true })
	const count = PublicKeyFieldCounts[type]
	if (count === undefined) {
		throw new Error(`unsupported public key type: ${type}`)
	}

	const { fields } = P.struct({ type: SSHText, fields: P.array(count, SSHBytes) }).decode(blob)

	return { type, fields }
}
