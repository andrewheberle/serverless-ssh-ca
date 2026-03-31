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
	getPublic,
    parseIdentity,
    refineCertificateRequest,
    refineHostCertificateRenewal,
    refineHostCertificateRequest,
    split,
    transformAuthorizationHeader,
    transformCertificate,
    transformHostProofOfPossession,
    transformProofOfPossession,
    transformPublicKey
} from "../utils"
import { KeyParseError, parsePrivateKey } from "sshpk"
import { CertificateType, getRevocationList, isRevoked, recordCertificate } from "../db"
import { KRLBuilder } from "../krl"

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
            const pub = await getPublic()

            return c.text(`${pub}\n`)
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

class UserCertificateRequestEndpoint extends OpenAPIRoute {
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
                    proof: z.string()
                        .transform(transformProofOfPossession)
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

        logger.info("handling user certificated request", "for", data.headers.Authorization.email)

        const identity = await parseIdentity(data.body.identity, c.env.JWT_SSH_CERTIFICATE_PRINCIPALS_CLAIM)
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
                await recordCertificate(certificate, data.headers.Authorization.email)
            } catch (err) {
                logger.error("there was a problem adding issued user certificate to database", "error", err)
            }

            return c.json(response)
        } catch (err) {
            // otherwise throw as InternalServerErrorException
            throw new InternalServerErrorException(`${err}`)
        }
    }
}
api.post("/user/certificate", UserCertificateRequestEndpoint)

class UserRevocationListEndpoint extends OpenAPIRoute {
    certificateType: CertificateType = CertificateType.User
    schema = {
        responses: {
            "200": {
                description: "Returns an Open SSH Key Revocation List as BASE64 and an SSHSIG signature for verification",
                ...contentJson(z.object({
                    krl: z.base64(),
                    signature: z.string()
                }))
            },
            ...InternalServerErrorException.schema(),
        }
    }

    async handle(c: AppContext) {
        try {
            // get revoked serials
            const serials = (await getRevocationList(this.certificateType)).map(v => BigInt(v))

            // grab private key from secret store
            const secret = await c.env.PRIVATE_KEY.get()

            // parse key
            const key = parsePrivateKey(secret)

            // generate KRL
            const krl = new KRLBuilder(key)
                .addSerials(serials)

            const krlBytes = krl.generate()

            // convert to base64
            const bytes = new Uint8Array(krlBytes)
            let binary = ""
            for (const byte of bytes) {
                binary += String.fromCharCode(byte)
            }
            const base64Krl = btoa(binary)

            const signature = await krl.signature()

            return c.json({
                krl: base64Krl,
                signature: signature,
            })
        } catch (err) {
            logger.error("krl error", "error", err)
            // otherwise throw as InternalServerErrorException
            throw new InternalServerErrorException(`${err}`)
        }
    }
}

api.get("/user/krl", UserRevocationListEndpoint)

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
                    proof: z.string()
                        .transform(transformHostProofOfPossession)
                        .describe("Proof of possession comprising of ${timestamp}.${fingerprint}.${format}:${signature}"),
					identity: z.string()
                        .describe("Identity Token JWT from OIDC IdP"),
                    principals: z.array(z.string()).min(1)
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

		const identity = await parseIdentity(data.body.identity, c.env.SSH_HOST_CERTIFICATE_ALLOWED_ROLES_CLAIM)
        if (identity.sub !== data.headers["Authorization"].sub) {
            throw new ForbiddenException("Possible token substitution as subjects for authentication and identity tokens did not match")
        }

        // check user can issue host certificates
        if (!split(env.SSH_HOST_CERTIFICATE_ALLOWED_EMAILS).includes(data.headers.Authorization.email) && !identity.principals.some((p: string) => split(env.SSH_HOST_CERTIFICATE_ALLOWED_ROLES).includes(p))) {
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

            try {
                await recordCertificate(certificate, `host_${certificate.subjects[0].hostname}`, CertificateType.Host)
            } catch (err) {
                logger.error("there was a problem adding issued host certificate to database", "error", err)
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
api.post("/host/certificate", HostCertificateRequestEndpoint)

class HostRevocationListEndpoint extends UserRevocationListEndpoint {
    certificateType: CertificateType = CertificateType.Host
}
api.get("/host/krl", HostRevocationListEndpoint)

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
                    proof: z.string()
                        .transform(transformHostProofOfPossession)
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

        // ensure certificate presented for renewal process is not revoked
        const serial = data.body.certificate.serial.readBigUInt64BE(0)
        if (await isRevoked(serial)) {
            throw new ForbiddenException("current certificate is revoked")
        }

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

            try {
                await recordCertificate(certificate, `host_${certificate.subjects[0].hostname}`, CertificateType.Host)
            } catch (err) {
                logger.error("there was a problem adding issued host certificate to database", "error", err)
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
