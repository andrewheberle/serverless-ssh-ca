import type { SshCaBindings } from "./types"
import { JWKInvalid, JWKSInvalid, JWSInvalid, JWTClaimValidationFailed, JWTInvalid } from "jose/errors"
import { Certificate, Key, KeyParseError, CertificateParseError, parseCertificate, parseKey, parsePrivateKey, PrivateKey } from "sshpk"
import z from "zod"
import { verifyJWT } from "./verify"
import { CertificateRequestJWTPayload } from "./types"
import { RenewalProofOfPossession, ProofOfPossession, PossessionParseError } from "./proof"
import type { isRevoked as IsRevokedFn } from "./db"
import { logger } from "./logger"
import { ms } from "itty-time"

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

type AccessToken = {
	email: string
	sub: string
}

export const transformAuthorizationHeader = async (env: SshCaBindings, val: string, ctx: z.RefinementCtx): Promise<AccessToken | never> => {
	const jwt = val.replace("Bearer ", "")
	const l = logger(env)

	if (jwt === "") {
		return fatalIssue(ctx, "request did not contain a JWT", val)
	}

	try {
		// verify jwt
		const { payload } = await verifyJWT(env, jwt)

		if (payload.email === undefined) {
			return fatalIssue(ctx, "JWT was verified but was missing required email claim", val)
		}

		return {
			email: payload.email,
			sub: payload.sub,
		}
	} catch (err) {
		switch (true) {
			case (err instanceof JWSInvalid):
				return fatalIssue(ctx, "the access token was invalid", val)
			case (err instanceof JWTInvalid):
				return fatalIssue(ctx, "the access token failed verification", val)
			case (err instanceof JWKInvalid):
				return fatalIssue(ctx, "the access token JWK was invalid", val)
			case (err instanceof JWKSInvalid):
				return fatalIssue(ctx, "the access token JWKS was invalid", val)
			case (err instanceof JWTClaimValidationFailed):
				return fatalIssue(ctx, "claim validtion of the JWT failed", val)
			default:
				l.error("unhandled access token validation error", "in", "transformAuthorizationHeader", "error", err)
				return fatalIssue(ctx, "unhandled access token validation error", val)
		}
	}
}

export const transformPublicKey = (val: string | Buffer<ArrayBufferLike>, ctx: z.RefinementCtx): Key | never => {
	try {
		const key = typeof val === "string" ? parseKey(Buffer.from(val, "base64")) : parseKey(val)

		return key
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

export const identityPrincipals = (env: SshCaBindings, payload: CertificateRequestJWTPayload, claim?: string): string[] => {
	if (claim === undefined) {
		claim = env.JWT_SSH_CERTIFICATE_PRINCIPALS_CLAIM
	}

	const l = logger(env)

	if (claim === "__proto__" || claim === "prototype" || claim === "constructor") {
 		l.warn("invalid principals claim configured", "claim", claim)
 		return []
 	}
 	const p = payload[claim]

	if (p === undefined) {
		l.warn("claim was missing despite being set in CA config", "claim", claim)
		return []
	}

	if (p === "") {
		l.warn("claim was present but was an empty string", "claim", claim)
		return []
	}

	// make sure its always a string[] and replace any spaces with underscores
	const principals = (typeof p === "string" ? [p] : p)
 		.map((value) => value.replaceAll(" ", "_"))

	l.info("identity token included principals", "principals", principals)

	return principals
}

type IdentityToken = {
	sub: string
	principals: string[]
}

export const parseIdentity = async (env: SshCaBindings, jwt: string | undefined, claim?: string): Promise<IdentityToken> => {
	if (jwt === undefined) {
		throw new Error("missing identity token")
	}

	const aud = env.JWT_AUD === undefined || env.JWT_AUD as string === "" ? undefined : split(env.JWT_AUD as string)
	const { payload } = await verifyJWT(env, jwt, { aud: aud })

	const principals = identityPrincipals(env, payload, claim)

	return {
		sub: payload.sub,
		principals: principals,
	}
}

export const transformIdentityToken = async (env: SshCaBindings, val: string, ctx: z.RefinementCtx): Promise<IdentityToken | never> => {
	try {
		const identity = await parseIdentity(env, val, env.JWT_SSH_CERTIFICATE_PRINCIPALS_CLAIM)

		return identity
	} catch (err) {
		ctx.issues.push({
			code: "custom",
			message: "problem parsing identity token",
			input: val
		})
		return z.NEVER
	}
}

/**
 *
 * @param val A SSH certificate either a base64 encoded "string" or a "Buffer\<ArrayBufferLike\>"
 * @param ctx The Zod context for any errors
 * @returns
 */
export const transformCertificate = (val: string | Buffer<ArrayBufferLike>, ctx: z.RefinementCtx): Certificate | never => {
	try {
		const cert = typeof val === "string" ? parseCertificate(Buffer.from(val, "base64"), "openssh") : parseCertificate(val, "openssh")

		return cert
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
	public_key: Key
	lifetime: number
	identity: IdentityToken
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
	public_key: Key
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
		l.debug("checking val.proof.matches()", "public_key", val.public_key.toString("ssh"))
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

type ParsedHostCertificateRenewal = {
	certificate: Certificate
	proof: RenewalProofOfPossession
} & HostCertificateRequest

export const refineHostCertificateRenewal = async (env: SshCaBindings, isRevoked: typeof IsRevokedFn, val: ParsedHostCertificateRenewal, ctx: z.RefinementCtx): Promise<never> => {
	const l = logger(env)
	try {
		// ensure certificate is signed by CA
		const issuer = await getPublic(env)
		if (!val.certificate.isSignedByKey(issuer)) {
			return fatalIssue(ctx, "the provided certificate was not signed by this CA", val)
		}

		// check certificate is not expired
		if (val.certificate.isExpired()) {
			return fatalIssue(ctx, "the provided certificate is expired", val)
		}

		// ensure certificate presented for renewal is not revoked
		const serial = val.certificate.serial.readBigUInt64BE(0)
		if (await isRevoked(env, serial)) {
			return fatalIssue(ctx, "the provided certificate is revoked", val)
		}

		// check proof of possession fingerprint matches public key and certificate subject key
		if (!val.proof.matches(val.public_key, val.certificate.subjectKey)) {
			return fatalIssue(ctx, "proof of possession fingerprints did not match public_key and/or certificate", val)
		}

		// verify proof of possession signature
		const verified = await val.proof.verify()
		if (!verified) {
			return fatalIssue(ctx, "proof of possession signature validation failed", val)
		}

		return z.NEVER
	} catch (err) {
		l.error("proof of possession verification unhandled error", "in", "refineHostCertificateRenewal", "error", err)
		return fatalIssue(ctx, "proof of possession verification unhandled error", val)
	}
}

type ParsedRevokeCertificate = {
	serial: bigint
	public_key: Key
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

export const split = (v: string): string[] => {
	if (v === "" || v === undefined) {
		return []
	}

	return v.split(",")
}

export const getPublic = async (env: SshCaBindings, key?: PrivateKey): Promise<Key> => {
	if (key === undefined) {
		// grab private key from secret store
		const secret = await env.PRIVATE_KEY.get()

		// parse it
		key = parsePrivateKey(secret)
	}

	// convert to a public key and add comment
	const pub = key.toPublic()
	pub.comment = env.ISSUER_DN

	// return in ssh format trimmed of any whitespace
	return pub
}
