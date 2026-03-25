import { Logger } from "@andrewheberle/ts-slog"
import {
    contentJson,
    ForbiddenException,
    fromHono,
    InputValidationException,
    InternalServerErrorException,
    OpenAPIRoute,
    UnprocessableEntityException
} from "chanfana"
import { Hono } from "hono"
import z from "zod"
import { AppContext } from "../router"
import { env } from "cloudflare:workers"
import { seconds } from "itty-time"
import { CertificateSignerResponse } from "../types"
import {
    BadIssuerError,
    CreateCertificateOptions,
    CreateHostCertificateOptions,
    createSignedCertificate,
    createSignedHostCertificate
} from "../certificate"
import {
    parseIdentity,
    refineCertificateRequest,
    refineHostCertificateRenewal,
    refineHostCertificateRequest,
    split,
    transformAuthorizationHeader,
    transformCertificate,
    transformHostNonce,
    transformNonce,
    transformPublicKey
} from "../utils"
import { Format, Identity, KeyParseError, parsePrivateKey } from "sshpk"
import { runStatement } from "../db"

const logger = new Logger()

export const api = fromHono(new Hono())

const HeaderSchema = z.object({
    "Authorization": z.string()
        .startsWith("Bearer ")
        .transform(transformAuthorizationHeader)
        .describe("Access Token JWT from OIDC IdP")
})

class CaPublicKeyEndpoint extends OpenAPIRoute {
    schema = {
        responses: {
            "200": {
                content: {
                    "text/plain": {
                        schema: z.string()
                    }
                },
                description: "Returns SSH Certificate Authority Public Key",
            },
            ...InternalServerErrorException.schema(),
        }
    }

    async handle(c: AppContext) {
        try {
            // grab private key from secret store (or env in tests)
            const secret = typeof c.env.PRIVATE_KEY === "string"
                ? c.env.PRIVATE_KEY
                : await c.env.PRIVATE_KEY.get()

            // parse key
            const key = parsePrivateKey(secret)
            const pub = key.toPublic()
            pub.comment = c.env.ISSUER_DN

            return c.text(`${pub.toString("ssh")}\n`)
        } catch (err) {
            if (err instanceof KeyParseError) {
                throw new InternalServerErrorException("Error parsing private key")
            }

            // otherwise throw as InternalServerErrorException
            throw new InternalServerErrorException(`${err}`)
        }
    }
}
api.get("/ca", CaPublicKeyEndpoint)

class CertificateRequestEndpoint extends OpenAPIRoute {
    schema = {
        security: [
            {
                oidcAuth: []
            }
        ],
        request: {
            headers: HeaderSchema,
            body: contentJson(
                z.object({
                    public_key: z.string()
                        .transform(transformPublicKey)
                        .describe("SSH public key to sign"),
                    nonce: z.string()
                        .transform(transformNonce)
                        .describe("Proof of possession comprising of ${timestamp}.${fingerprint}.${format}:${signature}"),
                    identity: z.string()
                        .describe("Identity Token JWT from OIDC IdP"),
                    extensions: z.array(z.string())
                        .default(split(env.SSH_CERTIFICATE_EXTENSIONS))
                        .describe("Extensions to include in issued SSH certificate in seconds"),
                    lifetime: z.number()
                        .min(seconds("5 minutes"))
                        .max(seconds(env.SSH_CERTIFICATE_LIFETIME))
                        .default(seconds(env.SSH_CERTIFICATE_LIFETIME))
                        .describe("Lifetime of issued SSH certificate"),
                })
                    .superRefine(refineCertificateRequest)
            )
        },
        responses: {
            "200": {
                description: "SSH User Certificate issued successfully",
                ...contentJson(z.object({
                    certificate: z.string(),
                }))
            },
            "401": {
                description: "Access to the endpoint is Unauthorized",
                ...contentJson(z.object({
                    error: z.literal("Unauthorized")
                }))
            },
            ...ForbiddenException.schema(),
            ...InputValidationException.schema(),
            ...UnprocessableEntityException.schema(),
            ...InternalServerErrorException.schema(),
        }
    }

    async handle(c: AppContext) {
        const data = await this.getValidatedData<typeof this.schema>()

        logger.info("handling renewal request", "for", data.headers.Authorization.email)

        const identity = await parseIdentity(data.body.identity)
        if (identity.sub !== data.headers["Authorization"].sub) {
            throw new ForbiddenException("Possible token substitution as subjects for authentication and identity tokens did not match")
        }

        const opts: CreateCertificateOptions = {
            lifetime: data.body.lifetime,
            principals: identity.principals,
            extensions: data.body.extensions,
        }

        try {
            const certificate = await createSignedCertificate(data.headers.Authorization.email, data.body.public_key, opts)
            const response: CertificateSignerResponse = {
                certificate: btoa(certificate.toString("openssh"))
            }

            try {
                const serial = certificate.serial.readBigUInt64BE(0)
                const subjects = certificate.subjects.map((v: Identity): string => {
                    return v.toString()
                }).join(",")
                const extensions = certificate.getExtensions().map((v: Format.OpenSshSignatureExt | Format.x509SignatureExt): string => {
                    // @ts-ignore: the name property does exist
                    return v.name as string
                }).join(",")
                const stmt = c.env.DB
                    .prepare("INSERT INTO certificates (serial, key_id, principals, extensions, valid_after, valid_before) VALUES (?, ?, ?, ?, ?, ?)")
                    .bind(`${serial}`, data.headers.Authorization.email, subjects, extensions, certificate.validFrom.toUTCString(), certificate.validUntil.toUTCString())
                const res = await runStatement(stmt)

                if (!res.success) {
                    if (res.error !== undefined) {
                        throw new Error(res.error)
                    }

                    throw new Error("error during query")
                }
            } catch (err) {
                logger.error("there was a problem adding issued certificate to database", "error", err)
            }

            return c.json(response)
        } catch (err) {
            // otherwise throw as InternalServerErrorException
            throw new InternalServerErrorException(`${err}`)
        }
    }
}
api.post("/certificate", CertificateRequestEndpoint)

class HostCertificateRequestEndpoint extends OpenAPIRoute {
    schema = {
        security: [
            {
                oidcAuth: []
            }
        ],
        request: {
            headers: HeaderSchema,
            body: contentJson(
                z.object({
                    public_key: z.string()
                        .transform(transformPublicKey)
                        .describe("SSH public key to sign"),
                    nonce: z.string()
                        .transform(transformNonce)
                        .describe("Proof of possession comprising of ${timestamp}.${fingerprint}.${format}:${signature}"),
                    principals: z.array(z.string())
                        .describe("List of principals to include on the issued certificate"),
                    lifetime: z.number()
                        .min(seconds("24 hours"))
                        .max(seconds(env.SSH_HOST_CERTIFICATE_LIFETIME))
                        .default(seconds(env.SSH_HOST_CERTIFICATE_LIFETIME))
                        .describe("Lifetime of issued Host SSH certificate"),
                })
                    .superRefine(refineHostCertificateRequest)
            )
        },
        responses: {
            "200": {
                description: "SSH Host Certificate issued successfully",
                ...contentJson(z.object({
                    certificate: z.string(),
                }))
            },
            "401": {
                description: "Access to the endpoint is Unauthorized",
                ...contentJson(z.object({
                    status: z.literal(401),
                    error: z.literal("Unauthorized")
                }))
            },
            ...ForbiddenException.schema(),
            ...InputValidationException.schema(),
            ...UnprocessableEntityException.schema(),
            ...InternalServerErrorException.schema(),
        }
    }

    async handle(c: AppContext) {
        const data = await this.getValidatedData<typeof this.schema>()

        logger.info("handling host certificate request", "for", data.headers.Authorization.email)

        // check user can issue host certificates
        if (!split(env.SSH_HOST_CERTIFICATE_ALLOWED_EMAILS).includes(data.headers.Authorization.email)) {
            throw new ForbiddenException("User not allowed to issue host certificates")
        }

        const opts: CreateHostCertificateOptions = {
            lifetime: data.body.lifetime,
            principals: data.body.principals,
        }

        try {
            const certificate = await createSignedHostCertificate(data.body.public_key, opts)
            const response: CertificateSignerResponse = {
                certificate: btoa(certificate.toString("openssh"))
            }

            return c.json(response)
        } catch (err) {
            switch (true) {
                case (err instanceof DOMException):
                    if (err.name === "InvalidCharacterError") {
                        throw new UnprocessableEntityException("The content was not valid base64 encoded data")
                    }
            }

            // otherwise throw as InternalServerErrorException
            throw new InternalServerErrorException(`${err}`)
        }
    }
}
api.post("/host/request", HostCertificateRequestEndpoint)

class HostCertificateRenewEndpoint extends OpenAPIRoute {
    schema = {
        request: {
            body: contentJson(
                z.object({
                    certificate: z.string()
                        .transform(transformCertificate)
                        .describe("SSH certificate to renew"),
                    public_key: z.string()
                        .transform(transformPublicKey)
                        .describe("SSH public key of certificate to be renewed"),
                    nonce: z.string()
                        .transform(transformHostNonce)
                        .describe("Proof of possession comprising of ${timestamp}.${keyfingerprint}.${format}:${signature}"),
                    lifetime: z.number()
                        .min(seconds("24 hours"))
                        .max(seconds(env.SSH_HOST_CERTIFICATE_LIFETIME))
                        .default(seconds(env.SSH_HOST_CERTIFICATE_LIFETIME))
                        .describe("Lifetime of renewed Host SSH certificate"),
                })
                    .superRefine(refineHostCertificateRenewal)
            )
        },
        responses: {
            "200": {
                description: "SSH Host Certificate renewed successfully",
                ...contentJson(z.object({
                    certificate: z.string(),
                }))
            },
            "401": {
                description: "Access to the endpoint is Unauthorized",
                ...contentJson(z.object({
                    status: z.literal(401),
                    error: z.literal("Unauthorized")
                }))
            },
            ...ForbiddenException.schema(),
            ...InputValidationException.schema(),
            ...UnprocessableEntityException.schema(),
            ...InternalServerErrorException.schema(),
        }
    }

    async handle(c: AppContext) {
        const data = await this.getValidatedData<typeof this.schema>()

        logger.info("handling host certificate renewal")

        // use smaller of the current certificate lifetime and the requested lifetime 
        const originalLifetime = (data.body.certificate.validUntil.getTime() - data.body.certificate.validFrom.getTime()) / 1000
        const lifetime = originalLifetime > data.body.lifetime
            ? data.body.lifetime
            : originalLifetime

        const opts: CreateHostCertificateOptions = {
            lifetime: lifetime,
            subjects: data.body.certificate.subjects
        }

        try {
            const certificate = await createSignedHostCertificate(data.body.public_key, opts)
            const response: CertificateSignerResponse = {
                certificate: btoa(certificate.toString("openssh"))
            }

            return c.json(response)
        } catch (err) {
            switch (true) {
                case (err instanceof DOMException):
                    if (err.name === "InvalidCharacterError") {
                        throw new UnprocessableEntityException("The content was not valid base64 encoded data")
                    }
                case (err instanceof BadIssuerError):
                    throw new UnprocessableEntityException(err.message)
            }

            // otherwise throw as InternalServerErrorException
            throw new InternalServerErrorException(`${err}`)
        }
    }
}
api.post("/host/renew", HostCertificateRenewEndpoint)
