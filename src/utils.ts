import { env } from "cloudflare:workers"
import { JWKInvalid, JWKSInvalid, JWSInvalid, JWTInvalid } from "jose/errors"
import { Key, KeyParseError, parseKey } from "sshpk"
import z from "zod"
import { verifyJWT } from "./verify"
import { CertificateRequestJWTPayload } from "./types"
import { Logger } from "@andrewheberle/ts-slog"
import { Nonce, NonceParseError } from "./nonce"

const logger = new Logger()

export const fatalIssue = (ctx: z.RefinementCtx, message: string) => {
    ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: message,
        fatal: true,
    })

    return z.NEVER
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
    if (env.IS_PRODUCTION as string === "false") {
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
    if (p === undefined) {
        logger.warn("principals claim was missing despite being set in CA config", "claim", env.JWT_SSH_CERTIFICATE_PRINCIPALS_CLAIM)
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

type ParsedCertificateRequest = {
    nonce: Nonce
    public_key: Key
    lifetime: number
    identity: string
    extensions: string[]
}

export const refineCertificateRequest = (val: ParsedCertificateRequest, ctx: z.RefinementCtx): never => {
    try {
        // check nonce fingerprint matches public key
        if (!val.nonce.fingerprint.matches(val.public_key)) {
            return fatalIssue(ctx, "nonce fingerprint did not match public_key")
        }

        // verify nonce signature
        if (!val.nonce.verify(val.public_key)) {
            return fatalIssue(ctx, "nonce signature validation failed")
        }

        return z.NEVER
    } catch (err) {
        return fatalIssue(ctx, "nonce verification unhandled error")
    }
}

type ParsedHostCertificateRequest = {
    nonce: Nonce
    public_key: Key
    lifetime: number
    principals: string[]
}

export const refineHostCertificateRequest = (val: ParsedHostCertificateRequest, ctx: z.RefinementCtx): never => {
    try {
        // check nonce fingerprint matches public key
        if (!val.nonce.fingerprint.matches(val.public_key)) {
            return fatalIssue(ctx, "nonce fingerprint did not match public_key")
        }

        // verify nonce signature
        if (!val.nonce.verify(val.public_key)) {
            return fatalIssue(ctx, "nonce signature validation failed")
        }

        return z.NEVER
    } catch (err) {
        return fatalIssue(ctx, "nonce verification unhandled error")
    }
}

export const split = (v: string): string[] => {
    return v.split(",")
}

