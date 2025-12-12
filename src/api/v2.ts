import { Logger } from "@andrewheberle/ts-slog"
import { contentJson, fromHono, InputValidationException, OpenAPIRoute } from "chanfana"
import { Hono } from "hono"
import { HTTPException } from "hono/http-exception"
import z from "zod"
import { AppContext } from "../router"
import { env } from "cloudflare:workers"
import { seconds } from "itty-time"
import { CertificateSignerResponse } from "../types"
import { BadIssuerError, CreateCertificateOptions, CreateHostCertificateOptions, createSignedCertificate, createSignedHostCertificate } from "../certificate"
import { parseIdentity, refineCertificateRequest, refineHostCertificateRenewal, refineHostCertificateRequest, split, transformAuthorizationHeader, transformCertificate, transformHostNonce, transformNonce, transformPublicKey } from "../utils"
import { KeyParseError, parsePrivateKey } from "sshpk"

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
            "500": {
                description: "There was an internal error",
                ...contentJson(z.object({
                    status: z.literal(500),
                    error: z.literal("Internal Server Error")
                }))
            }
        }
    }

    async handle(c: AppContext) {
        try {
            const key = parsePrivateKey(await c.env.PRIVATE_KEY.get())
            const pub = key.toPublic()
            pub.comment = c.env.ISSUER_DN

            return c.text(`${pub.toString("ssh")}\n`)
        } catch (err) {
            if (err instanceof KeyParseError) {
                throw new HTTPException(500, { message: "error parsing private key", cause: err})
            }

            throw err
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
                    status: z.literal(401),
                    error: z.literal("Unauthorized")
                }))
            },
            "403": {
                description: "Access to the endpoint is Forbidden",
                ...contentJson(z.object({
                    status: z.literal(403),
                    error: z.literal("Forbidden")
                }))
            },
            ...InputValidationException.schema(),
            "422": {
                description: "The request to could not be processed",
                ...contentJson(z.object({
                    status: z.literal(422),
                    error: z.literal("Unprocessable Entity")
                }))
            },
            "500": {
                description: "There was an internal error",
                ...contentJson(z.object({
                    status: z.literal(500),
                    error: z.literal("Internal Server Error")
                }))
            }
        }
    }

    async handle(c: AppContext) {
        try {
            const data = await this.getValidatedData<typeof this.schema>()

            logger.info("handling renewal request", "for", data.headers.Authorization.email)

            const identity = await parseIdentity(data.body.identity)
            if (identity.sub !== data.headers["Authorization"].sub) {
                throw new HTTPException(403, { message: "possible token substitution as subjects for authentication and identity tokens did not match" })
            }

            const opts: CreateCertificateOptions = {
                lifetime: data.body.lifetime,
                principals: identity.principals,
                extensions: data.body.extensions,
            }

            const certificate = await createSignedCertificate(data.headers.Authorization.email, data.body.public_key, opts)
            const response: CertificateSignerResponse = {
                certificate: btoa(certificate.toString("openssh"))
            }

            return c.json(response)
        } catch (err) {
            switch (true) {
                case (err instanceof DOMException):
                    if (err.name === "InvalidCharacterError") {
                        throw new HTTPException(422, { message: "the content was not valid base64 encoded data", cause: err })
                    }
            }

            // otherwise just re-throw error
            logger.error("unhandled error", "error", err)
            throw err
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
            "403": {
                description: "Access to the endpoint is Forbidden",
                ...contentJson(z.object({
                    status: z.literal(403),
                    error: z.literal("Forbidden")
                }))
            },
            ...InputValidationException.schema(),
            "422": {
                description: "The request to could not be processed",
                ...contentJson(z.object({
                    status: z.literal(422),
                    error: z.literal("Unprocessable Entity")
                }))
            },
            "500": {
                description: "There was an internal error",
                ...contentJson(z.object({
                    status: z.literal(500),
                    error: z.literal("Internal Server Error")
                }))
            }
        }
    }

    async handle(c: AppContext) {
        try {
            const data = await this.getValidatedData<typeof this.schema>()

            logger.info("handling host certificate request", "for", data.headers.Authorization.email)

            // check user can issue host certificates
            if (!split(env.SSH_HOST_CERTIFICATE_ALLOWED_EMAILS).includes(data.headers.Authorization.email)) {
                throw new HTTPException(403, { message: "user not allowed to issue host certificates" })
            }

            const opts: CreateHostCertificateOptions = {
                lifetime: data.body.lifetime,
                principals: data.body.principals,
            }

            const certificate = await createSignedHostCertificate(data.body.public_key, opts)
            const response: CertificateSignerResponse = {
                certificate: btoa(certificate.toString("openssh"))
            }

            return c.json(response)
        } catch (err) {
            switch (true) {
                case (err instanceof DOMException):
                    if (err.name === "InvalidCharacterError") {
                        throw new HTTPException(422, { message: "the content was not valid base64 encoded data", cause: err })
                    }
            }

            // otherwise just re-throw error
            logger.error("unhandled error", "error", err)
            throw err
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
                        .describe("Proof of possession comprising of ${timestamp}.${keyfingerprint}.${certfingerprint}.${format}:${signature}"),
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
            "403": {
                description: "Access to the endpoint is Forbidden",
                ...contentJson(z.object({
                    status: z.literal(403),
                    error: z.literal("Forbidden")
                }))
            },
            ...InputValidationException.schema(),
            "422": {
                description: "The request to could not be processed",
                ...contentJson(z.object({
                    status: z.literal(422),
                    error: z.literal("Unprocessable Entity")
                }))
            },
            "500": {
                description: "There was an internal error",
                ...contentJson(z.object({
                    status: z.literal(500),
                    error: z.literal("Internal Server Error")
                }))
            }
        }
    }

    async handle(c: AppContext) {
        try {
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

            const certificate = await createSignedHostCertificate(data.body.public_key, opts)
            const response: CertificateSignerResponse = {
                certificate: btoa(certificate.toString("openssh"))
            }

            return c.json(response)
        } catch (err) {
            switch (true) {
                case (err instanceof DOMException):
                    if (err.name === "InvalidCharacterError") {
                        throw new HTTPException(422, { message: "the content was not valid base64 encoded data", cause: err })
                    }
                case (err instanceof BadIssuerError):
                    throw new HTTPException(422, { message: err.message })
            }

            // otherwise just re-throw error
            logger.error("unhandled error", "error", err)
            throw err
        }
    }
}
api.post("/host/renew", HostCertificateRenewEndpoint)
