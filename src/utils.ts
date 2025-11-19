import { env } from "cloudflare:workers"
import { ms } from "itty-time"
import { JWKInvalid, JWKSInvalid, JWSInvalid, JWTInvalid } from "jose/errors"
import { Fingerprint, FingerprintFormatError, Key, KeyParseError, parseFingerprint, parseKey, parseSignature, Signature, SignatureParseError } from "sshpk"
import z from "zod"
import { verifyJWT } from "./verify"
import { CertificateRequestJWTPayload } from "./types"
import { Logger } from "@andrewheberle/ts-slog"

const logger = new Logger()

export const fatalIssue = (ctx: z.RefinementCtx, message: string) => {
    ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: message,
        fatal: true,
    })

    return z.NEVER
}

type ParsedNonce = {
    timestamp: number
    fingerprint: Fingerprint
    signature: Signature
    dataToVerify: string
}

export class NonceParseError extends Error {
    constructor(message: string) {
        super(message)
        this.name = "NonceParseError"

        // This is necessary for proper stack trace in TypeScript
        Object.setPrototypeOf(this, NonceParseError.prototype)
    }
}

class Nonce {
    readonly timestamp: number
    readonly fingerprint: Fingerprint
    readonly signature: Signature
    private readonly dataToVerify: string

    constructor(nonce: string) {
        const parts = nonce.split(".")
        if (parts.length !== 3) {
            throw new NonceParseError("invalid nonce format")
        }

        const [timestampStr, fingerprintHex, signatureBase64] = parts

        // verify timestamp
        const timestamp: number = parseInt(timestampStr, 10)
        if (isNaN(timestamp)) {
            throw new NonceParseError("timestamp was not a number")
        }

        const now = Date.now()
        const age = now - timestamp
        if (age > ms(env.CERTIFICATE_REQUEST_TIME_SKEW_MAX)) {
            throw new NonceParseError("nonce timestamp too old")
        }

        // verify fingerprint matches public key
        try {
            const fingerprint = parseFingerprint(fingerprintHex)
            if (fingerprint === undefined) {
                throw new NonceParseError("nonce fingerprint did not parse")
            }

            // parse signature
            const signature = parseSignature(signatureBase64, "ecdsa", "ssh")

            // set our values
            this.timestamp = timestamp
            this.fingerprint = fingerprint
            this.signature = signature
            this.dataToVerify = `${timestamp}.${fingerprintHex}`
        } catch (err) {
            switch (true) {
                case (err instanceof FingerprintFormatError):
                    throw new NonceParseError("nonce fingerprint was an invalid format")
                case (err instanceof SignatureParseError):
                    throw new NonceParseError("nonce signature could not be parsed")
                default:
                    throw err
            }
        }
    }

    /**
     * 
     * @param key public key to use to verify fingerprint and signature against
     * @returns true or false if verification succeeds
     */
    verify(key: Key) {
        // create verifier from public key
        const verifier = key.createVerify("sha256")
        verifier.update(this.dataToVerify)

        return verifier.verify(this.signature)
    }
}


export const transformNonce = (val: string, ctx: z.RefinementCtx): Nonce | never => {
    try {
        return new Nonce(val)
    } catch (err) {
        if (err instanceof NonceParseError) {
            return fatalIssue(ctx, err.message)
        }

        return fatalIssue(ctx, "nonce transform unhandled error")
    }
}

type ParsedAuthorizationHeader = {
    email: string
    sub: string
}

export const transformAuthorizationHeader = async (val: string, ctx: z.RefinementCtx): Promise<ParsedAuthorizationHeader | never> => {
    // skip this when running locally
    if (env.IS_PRODUCTION === "false") {
        return {
            email: "text@example.com",
            sub: "test",
        }
    }

    const jwt = val.replace("Bearer ", "")

    if (jwt === "") {
        return fatalIssue(ctx, "request did not contain a JWT")
    }

    try {
        // verify jwt 
        const { payload } = await verifyJWT(jwt)

        if (payload.email === undefined) {
            return fatalIssue(ctx, "JWT was verified but was missing required email claim")
        }

        return {
            email: payload.email,
            sub: payload.sub,
        }
    } catch (err) {
        switch (true) {
            case (err instanceof JWSInvalid):
                return fatalIssue(ctx, "the access token was invalid")
            case (err instanceof JWTInvalid):
                return fatalIssue(ctx, "the access token failed verification")
            case (err instanceof JWKInvalid):
                return fatalIssue(ctx, "the access token JWK was invalid")
            case (err instanceof JWKSInvalid):
                return fatalIssue(ctx, "the access token JWK was invalid")
            default:
                return fatalIssue(ctx, "unhandled access token validation error")
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
                    ctx.addIssue({
                        code: z.ZodIssueCode.custom,
                        message: "the content was not valid base64 encoded data"
                    })
                } else {
                    ctx.addIssue({
                        code: z.ZodIssueCode.custom,
                        message: "unhandled error parsing base64 public_key"
                    })
                }
            case (err instanceof KeyParseError):
                ctx.addIssue({
                    code: z.ZodIssueCode.custom,
                    message: err.message
                })
            default:
                ctx.addIssue({
                    code: z.ZodIssueCode.custom,
                    message: "unhandled error parsing public_key"
                })
        }

        return z.NEVER
    }
}

const identityPrincipals = (payload: CertificateRequestJWTPayload): string[] => {
    if (env.JWT_SSH_CERTIFICATE_PRINCIPALS_CLAIM === undefined) {
        return []
    }

    const p = payload[env.JWT_SSH_CERTIFICATE_PRINCIPALS_CLAIM]

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

type ParsedCertificateRequest = {
    nonce: Nonce
    public_key: Key
    lifetime: number
    identity: string
    extensions: string[]
}

export const refineCertificateRequest = (val: ParsedCertificateRequest, ctx: z.RefinementCtx) => {
    try {
        // verify nonce signature
        if (!val.nonce.verify(val.public_key)) {
            return fatalIssue(ctx, "nonce signature validation failed")
        }

        return z.NEVER
    } catch (err) {
        if (err instanceof NonceVerifyError) {
            return fatalIssue(ctx, err.message)
        }

        return fatalIssue(ctx, "nonce verification unhandled error")
    }
}
