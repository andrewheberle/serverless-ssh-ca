import type { SshCaBindings } from "./types.js"
import { CertificateParseError, SshCertificate } from "./ssh/certificate.js"
import { KeyParseError, MinimumRsaKeyBits, parsePrivateKey, PublicKey, rsaKeyBits, UnsupportedKeyError, type PrivateKey } from "./ssh/keys.js"
import z from "zod"
import { RenewalProofOfPossession, ProofOfPossession, PossessionParseError } from "./proof.js"
import { logger } from "./logger.js"
import { ms } from "itty-time"

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
		const proof = new ProofOfPossession(val, { logger: l, skew: ms(env.CERTIFICATE_REQUEST_TIME_SKEW_MAX) })

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

type ParsedCertificateRequest = {
	proof: ProofOfPossession
	public_key: PublicKey
	lifetime: number
	identity: string
	extensions: string[]
}

export const refineCertificateRequest = async (env: SshCaBindings, val: ParsedCertificateRequest, ctx: z.RefinementCtx): Promise<never> => {
	const l = logger(env)
	try {
		// check proof of possession fingerprint matches public key
		if (!val.proof.matches(val.public_key)) {
			return fatalIssue(ctx, "proof of possession fingerprint did not match public_key", val)
		}

		// verify proof of possession signature
		const verified = await val.proof.verify()
		if (!verified) {
			return fatalIssue(ctx, "proof of possession signature validation failed", val)
		}

		return z.NEVER
	} catch (err) {
		l.error("proof of possession verification unhandled error", "in", "refineCertificateRequest", "error", err)
		return fatalIssue(ctx, "proof of possession verification unhandled error", val)
	}
}

export const transformRenewalProofOfPossession = (env: SshCaBindings, val: string, ctx: z.RefinementCtx): RenewalProofOfPossession | never => {
	const l = logger(env)
	try {
		return new RenewalProofOfPossession(val, { logger: l, skew: ms(env.CERTIFICATE_REQUEST_TIME_SKEW_MAX) })
	} catch (err) {
		if (err instanceof PossessionParseError) {
			return fatalIssue(ctx, err.message, val)
		}

		l.error("proof of possession verification unhandled error", "in", "transformRenewalProofOfPossession", "error", err)
		return fatalIssue(ctx, "proof of possession transform unhandled error", val)
	}
}

type HostCertificateRequest = {
	public_key: PublicKey
	lifetime: number
}

type ParsedHostCertificateRequest = {
	principals: string[]
	proof: ProofOfPossession
} & HostCertificateRequest

export const refineHostCertificateRequest = async (env: SshCaBindings, val: ParsedHostCertificateRequest, ctx: z.RefinementCtx): Promise<never> => {
	const l = logger(env).with("in", "refineHostCertificateRequest")

	l.debug("started")

	try {
		// check proof of possession fingerprint matches public key
		l.debug("checking val.proof.matches()", "public_key", val.public_key.toString())
		if (!val.proof.matches(val.public_key)) {
			l.warn("proof of possession fingerprint did not match public_key")
			return fatalIssue(ctx, "proof of possession fingerprint did not match public_key", val)
		}

		// verify proof of possession signature
		l.debug("await val.proof.verify()")
		const verified = await val.proof.verify()
		if (!verified) {
			l.warn("proof of possession signature validation failed")
			return fatalIssue(ctx, "proof of possession signature validation failed", val)
		}

		l.debug("done")

		return z.NEVER
	} catch (err) {
		l.error("proof of possession verification unhandled error", "error", err)
		return fatalIssue(ctx, "proof of possession verification unhandled error", val)
	}
}

// characters that OpenSSH treats as pattern syntax when matching host
// certificate principals, or that separate entries in a pattern list
const HostPrincipalPatternChars = /[*?!,]/
// whitespace and control characters, which no host name contains
const HostPrincipalInvalidChars = /[\s\p{Cc}]/u

/**
 * Returns why a principal cannot be included on a host certificate, or
 * undefined if it can be.
 *
 * OpenSSH matches the principals of a host certificate as patterns, so a
 * principal such as `*` would make the certificate valid for every host that
 * trusts the CA. Principals are otherwise not restricted, as hosts may be
 * reached by IP address, bare host name or fully qualified domain name.
 *
 * @param principal The principal to check
 * @returns The reason the principal cannot be used, or undefined if it can be
 */
export const hostPrincipalIssue = (principal: string): string | undefined => {
	if (principal === "") {
		return "host certificate principals must not be empty"
	}

	if (HostPrincipalPatternChars.test(principal)) {
		return `host certificate principal ${JSON.stringify(principal)} must not contain wildcard or pattern characters (*, ?, ! or ,)`
	}

	if (HostPrincipalInvalidChars.test(principal)) {
		return `host certificate principal ${JSON.stringify(principal)} must not contain whitespace or control characters`
	}

	return undefined
}

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

type ParsedHostCertificateRenewal = {
	certificate: SshCertificate
	proof: RenewalProofOfPossession
	public_key: PublicKey
}

/**
 * Refines a v3 host certificate renewal so it is only accepted with a proof of
 * possession of the key of the certificate presented. Whether the certificate
 * can be renewed is checked once possession of its key is proven, see
 * `renewHostCertificate`.
 */
export const refineRenewalProof = async (env: SshCaBindings, val: ParsedHostCertificateRenewal, ctx: z.RefinementCtx): Promise<never> => {
	const l = logger(env)
	try {
		// check proof of possession fingerprint matches public key and certificate subject key
		if (!val.proof.matches(val.public_key, val.certificate.publicKey)) {
			return fatalIssue(ctx, "proof of possession fingerprints did not match public_key and/or certificate", val)
		}

		// verify proof of possession signature
		const verified = await val.proof.verify()
		if (!verified) {
			return fatalIssue(ctx, "proof of possession signature validation failed", val)
		}

		return z.NEVER
	} catch (err) {
		l.error("proof of possession verification unhandled error", "in", "refineRenewalProof", "error", err)
		return fatalIssue(ctx, "proof of possession verification unhandled error", val)
	}
}

type ParsedRevokeCertificate = {
	serial: bigint
	public_key: PublicKey
	proof: ProofOfPossession
}

export const refineRevokeCertificate = async (env: SshCaBindings, val: ParsedRevokeCertificate, ctx: z.RefinementCtx): Promise<never> => {
	const l = logger(env)
	try {
		// check proof of possession fingerprint matches public key
		if (!val.proof.matches(val.public_key)) {
			return fatalIssue(ctx, "proof of possession fingerprint did not match public_key", val)
		}

		// verify proof of possession signature
		const verified = await val.proof.verify()
		if (!verified) {
			return fatalIssue(ctx, "proof of possession signature validation failed", val)
		}

		return z.NEVER
	} catch (err) {
		l.error("proof of possession verification unhandled error", "in", "refineRevokeCertificate", "error", err)
		return fatalIssue(ctx, "proof of possession verification unhandled error", val)
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
