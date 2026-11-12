import type { SshCaBindings } from "./types.js"
import { CertificateParseError, SshCertificate } from "./ssh/certificate.js"
import { KeyParseError, MinimumRsaKeyBits, parsePrivateKey, PublicKey, rsaKeyBits, UnsupportedKeyError, type PrivateKey } from "./ssh/keys.js"
import z from "zod"
import { ProofOfPossession, PossessionParseError } from "./proof.js"
import { logger } from "./logger.js"
import { caConfig } from "./config.js"
import { principalIssue } from "./principals.js"

export { UnsupportedKeyError }

export const fatalIssue = (ctx: z.RefinementCtx, message: string, val: unknown) => {
	ctx.issues.push({
		code: "custom",
		message: message,
		input: val
	})

	return z.NEVER
}

export const transformProofOfPossession = (env: SshCaBindings, val: string, ctx: z.core.$RefinementCtx<string>): ProofOfPossession | never => {
	const l = logger(env)
	try {
		const proof = new ProofOfPossession(val, { logger: l, skew: caConfig(env).requestTimeSkewMax })

		return proof
	} catch (err) {
		l.error("proof of possession parsing error", "error", err)
		switch (true) {
			case (err instanceof PossessionParseError):
				ctx.issues.push({
					code: "custom",
					message: err.message,
					input: val
				})
				break
			default:
				ctx.issues.push({
					code: "custom",
					message: "proof of possession transform unhandled error",
					input: val
				})
		}

		return z.NEVER
	}
}

// decodes a value sent as base64, which may already have been decoded by the schema
const fromBase64 = (val: string | Buffer<ArrayBufferLike>): string => {
	return (typeof val === "string" ? Buffer.from(val, "base64") : Buffer.from(val)).toString("utf8")
}

/**
 * Parses a public key in OpenSSH format, `${type} ${base64}[ ${comment}]`
 *
 * @param val The public key, either base64 encoded or as bytes
 * @param ctx The Zod context for any errors
 */
export const transformPublicKey = (val: string | Buffer<ArrayBufferLike>, ctx: z.RefinementCtx): PublicKey | never => {
	try {
		return PublicKey.parse(fromBase64(val))
	} catch (err) {
		switch (true) {
			case (err instanceof TypeError):
				ctx.issues.push({
					code: "custom",
					message: err.message,
					input: val
				})
				break
			case (err instanceof KeyParseError):
				ctx.issues.push({
					code: "custom",
					message: err.message,
					input: val
				})
				break
			default:
				ctx.issues.push({
					code: "custom",
					message: "unhandled error parsing public_key",
					input: val
				})
		}

		return z.NEVER
	}
}

/**
 * Returns why a public key cannot be issued a certificate, or undefined if it
 * can be.
 *
 * RSA keys must be at least {@link MinimumRsaKeyBits} bits, as smaller keys
 * can be factored and are refused by current OpenSSH releases.
 *
 * @param key The public key a certificate would be issued for
 * @returns The reason the key cannot be used, or undefined if it can be
 */
export const subjectKeyIssue = (key: PublicKey): string | undefined => {
	const bits = rsaKeyBits(key)
	if (bits !== undefined && bits < MinimumRsaKeyBits) {
		return `RSA keys must be at least ${MinimumRsaKeyBits} bits, not ${bits}`
	}

	return undefined
}

/**
 * Refines a public key so only one allowed by {@link subjectKeyIssue} is
 * accepted for a certificate request.
 */
export const refineSubjectKey = (val: PublicKey, ctx: z.RefinementCtx): void => {
	const issue = subjectKeyIssue(val)
	if (issue !== undefined) {
		fatalIssue(ctx, issue, val.toString())
	}
}

/**
 *
 * @param val A SSH certificate either a base64 encoded "string" or a "Buffer\<ArrayBufferLike\>"
 * @param ctx The Zod context for any errors
 * @returns
 */
export const transformCertificate = (val: string | Buffer<ArrayBufferLike>, ctx: z.RefinementCtx): SshCertificate | never => {
	try {
		return SshCertificate.parse(fromBase64(val))
	} catch (err) {
		switch (true) {
			case (err instanceof TypeError):
				ctx.issues.push({
					code: "custom",
					message: err.message,
					input: val
				})
				break
			case (err instanceof CertificateParseError):
				ctx.issues.push({
					code: "custom",
					message: err.message,
					input: val
				})
				break
			default:
				ctx.issues.push({
					code: "custom",
					message: "unhandled error parsing certificate",
					input: val
				})
		}

		return z.NEVER
	}
}

/**
 * Returns why a principal cannot be included on a host certificate, or
 * undefined if it can be, see {@link principalIssue}.
 *
 * @param principal The principal to check
 * @returns The reason the principal cannot be used, or undefined if it can be
 */
export const hostPrincipalIssue = (principal: string): string | undefined => principalIssue("host", principal)

/**
 * Refines a host certificate principal so only one allowed by
 * {@link hostPrincipalIssue} is accepted.
 */
export const refineHostPrincipal = (val: string, ctx: z.RefinementCtx): void => {
	const issue = hostPrincipalIssue(val)
	if (issue !== undefined) {
		fatalIssue(ctx, issue, val)
	}
}

export const split = (v?: string | string[]): string[] => {
	return v === undefined
		? []
		: typeof v === "string"
			? v === ""
				? []
				: v.split(",")
			: v
}

/**
 * Load and parse the CA private key from the `PRIVATE_KEY` secret.
 *
 * Only Ed25519 and ECDSA keys are supported, as these are the key types that
 * certificates and KRLs are signed with (see `createSigner` in `ssh/signer.ts`).
 *
 * @throws {@link KeyParseError} when the secret cannot be parsed.
 * @throws {@link UnsupportedKeyError} when the key is not Ed25519 or ECDSA.
 */
export const getPrivateKey = async (env: Pick<SshCaBindings, "PRIVATE_KEY">): Promise<PrivateKey> => {
	// grab private key from secret store
	const secret = await env.PRIVATE_KEY.get()

	return parsePrivateKey(secret)
}

/**
 * Returns the public key of the CA, with `ISSUER_DN` as its comment
 */
export const getPublic = async (env: Pick<SshCaBindings, "PRIVATE_KEY" | "ISSUER_DN">, key?: PrivateKey): Promise<PublicKey> => {
	if (key === undefined) {
		key = await getPrivateKey(env)
	}

	return key.publicKey.withComment(env.ISSUER_DN)
}
