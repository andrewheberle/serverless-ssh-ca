import { env } from "cloudflare:workers"
import { JWKInvalid, JWKSInvalid, JWSInvalid, JWTInvalid } from "jose/errors"
import { Certificate, Key, KeyParseError, CertificateParseError, parseCertificate, parseKey, parsePrivateKey, PrivateKey } from "sshpk"
import z from "zod"
import { verifyJWT } from "./verify"
import { CertificateRequestJWTPayload } from "./types"
import { Logger } from "@andrewheberle/ts-slog"
import { HostProofOfPossession, ProofOfPossession, PossessionParseError } from "./proof"

const logger = new Logger()

export const fatalIssue = (ctx: z.RefinementCtx, message: string, val: unknown) => {
    ctx.issues.push({
        code: "custom",
        message: message,
        input: val
    })

    return z.NEVER
}

export const transformProofOfPossession = (val: string, ctx: z.core.$RefinementCtx<string>): ProofOfPossession | never => {
    try {
        const proof = new ProofOfPossession(val)

        return proof
    } catch (err) {
        logger.error("proof of possession parsing error", "error", err)
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

type ParsedAuthorizationHeader = {
    email: string
    sub: string
}

export const transformAuthorizationHeader = async (val: string, ctx: z.RefinementCtx): Promise<ParsedAuthorizationHeader | never> => {
    // skip this when running locally
    if (env.IS_PRODUCTION as string === "false") {
        return {
            email: "text@example.com",
            sub: "test",
        }
    }

    const jwt = val.replace("Bearer ", "")

    if (jwt === "") {
        return fatalIssue(ctx, "request did not contain a JWT", val)
    }

    try {
        // verify jwt
        const { payload } = await verifyJWT(jwt)

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
                return fatalIssue(ctx, "the access token JWK was invalid", val)
            default:
                return fatalIssue(ctx, "unhandled access token validation error", val)
        }
    }
}

export const transformPublicKey = (val: string, ctx: z.RefinementCtx): Key | never => {
    try {
        const decoded = atob(val)
        const key = parseKey(decoded)

        return key
    } catch (err) {
        switch (true) {
            case (err instanceof DOMException):
                if (err.name === "InvalidCharacterError") {
                    ctx.issues.push({
                        code: "custom",
                        message: "not valid base64 encoded data",
                        input: val
                    })
                } else {
                    ctx.issues.push({
                        code: "custom",
                        message: "unhandled error parsing base64 public_key",
                        input: val
                    })
                }
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

export const identityPrincipals = (payload: CertificateRequestJWTPayload): string[] => {
    if (env.JWT_SSH_CERTIFICATE_PRINCIPALS_CLAIM === undefined) {
        return []
    }

    const p = payload[env.JWT_SSH_CERTIFICATE_PRINCIPALS_CLAIM]
    if (p === undefined) {
        logger.warn("principals claim was missing despite being set in CA config", "claim", env.JWT_SSH_CERTIFICATE_PRINCIPALS_CLAIM)
        return []
    }

    if (p === "") {
        logger.warn("principals claim was present but was an empty string", "claim", env.JWT_SSH_CERTIFICATE_PRINCIPALS_CLAIM)
        return []
    }

    // make sure its always a string[]
    const principals = typeof p === "string" ? [p] : p

    // replace any spaces with underscores
    principals.forEach((value, index, array) => {
        array[index] = value.replaceAll(" ", "_")
    })

    logger.info("identity token included principals", "principals", principals)

    return principals
}

type ParsedIdentity = {
    sub: string
    principals: string[]
}

export const parseIdentity = async (jwt: string | undefined): Promise<ParsedIdentity> => {
    if (jwt === undefined) {
        return {
            sub: "",
            principals: []
        }
    }

    const { payload } = await verifyJWT(jwt)

    const principals = identityPrincipals(payload)

    return {
        sub: payload.sub,
        principals: principals,
    }
}

export const transformCertificate = (val: string, ctx: z.RefinementCtx): Certificate | never => {
    try {
        const decoded = atob(val)
        const cert = parseCertificate(decoded, "openssh")

        return cert
    } catch (err) {
        switch (true) {
            case (err instanceof DOMException):
                if (err.name === "InvalidCharacterError") {
                    ctx.issues.push({
                        code: "custom",
                        message: "the content was not valid base64 encoded data",
                        input: val
                    })
                } else {
                    ctx.issues.push({
                        code: "custom",
                        message: "unhandled error parsing base64 certificate",
                        input: val
                    })
                }
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
    identity: string
    extensions: string[]
}

export const refineCertificateRequest = async (val: ParsedCertificateRequest, ctx: z.RefinementCtx): Promise<never> => {
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
        return fatalIssue(ctx, "proof of possession verification unhandled error", val)
    }
}

type LegacyParsedCertificateRequest = {
    nonce: ProofOfPossession
    public_key: Key
    lifetime: number
    identity: string
    extensions: string[]
}

export const refineLegacyCertificateRequest = async (val: LegacyParsedCertificateRequest, ctx: z.RefinementCtx): Promise<never> => {
    try {
        // check proof of possession fingerprint matches public key
        if (!val.nonce.matches(val.public_key)) {
            return fatalIssue(ctx, "proof of possession fingerprint did not match public_key", val)
        }

        // verify proof of possession signature
        const verified = await val.nonce.verify()
        if (!verified) {
            return fatalIssue(ctx, "proof of possession signature validation failed", val)
        }

        return z.NEVER
    } catch (err) {
        return fatalIssue(ctx, "proof of possession verification unhandled error", val)
    }
}

export const transformHostProofOfPossession = (val: string, ctx: z.RefinementCtx): HostProofOfPossession | never => {
    try {
        return new HostProofOfPossession(val)
    } catch (err) {
        if (err instanceof PossessionParseError) {
            return fatalIssue(ctx, err.message, val)
        }

        return fatalIssue(ctx, "host proof of possession transform unhandled error", val)
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

export const refineHostCertificateRequest = async (val: ParsedHostCertificateRequest, ctx: z.RefinementCtx): Promise<never> => {
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
        return fatalIssue(ctx, "proof of possession verification unhandled error", val)
    }
}

type LegacyParsedHostCertificateRequest = {
    principals: string[]
    nonce: ProofOfPossession
} & HostCertificateRequest

export const refineLegacyHostCertificateRequest = async (val: LegacyParsedHostCertificateRequest, ctx: z.RefinementCtx): Promise<never> => {
    try {
        // check proof of possession fingerprint matches public key
        if (!val.nonce.matches(val.public_key)) {
            return fatalIssue(ctx, "proof of possession fingerprint did not match public_key", val)
        }

        // verify proof of possession signature
        const verified = await val.nonce.verify()
        if (!verified) {
            return fatalIssue(ctx, "proof of possession signature validation failed", val)
        }

        return z.NEVER
    } catch (err) {
        return fatalIssue(ctx, "proof of possession verification unhandled error", val)
    }
}

type ParsedHostCertificateRenewal = {
    certificate: Certificate
    proof: HostProofOfPossession
} & HostCertificateRequest

export const refineHostCertificateRenewal = async (val: ParsedHostCertificateRenewal, ctx: z.RefinementCtx): Promise<never> => {
    try {
        // check certificate is not expired
        if (val.certificate.isExpired()) {
            return fatalIssue(ctx, "certificate is expired", val)
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
        return fatalIssue(ctx, "proof of possession verification unhandled error", val)
    }
}

type LegacyParsedHostCertificateRenewal = {
    certificate: Certificate
    nonce: ProofOfPossession
} & HostCertificateRequest

export const refineLegacyHostCertificateRenewal = async (val: LegacyParsedHostCertificateRenewal, ctx: z.RefinementCtx): Promise<never> => {
    try {
        // check certificate is not expired
        if (val.certificate.isExpired()) {
            return fatalIssue(ctx, "certificate is expired", val)
        }

        // check proof of possession fingerprint matches public key and certificate subject key
        if (!val.nonce.matches(val.public_key, val.certificate.subjectKey)) {
            return fatalIssue(ctx, "proof of possession fingerprints did not match public_key and/or certificate", val)
        }

        // verify proof of possession signature
        const verified = await val.nonce.verify()
        if (!verified) {
            return fatalIssue(ctx, "proof of possession signature validation failed", val)
        }

        return z.NEVER
    } catch (err) {
        return fatalIssue(ctx, "proof of possession verification unhandled error", val)
    }
}

export const split = (v: string): string[] => {
    if (v === "") {
        return []
    }

    return v.split(",")
}

export const getPublic = async (key?: PrivateKey) => {
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
	return pub.toString("ssh").trim()
}
