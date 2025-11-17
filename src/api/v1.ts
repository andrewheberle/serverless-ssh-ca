import { error, text } from "itty-router"
import { CFArgs } from "../router"
import { parsePrivateKey } from "sshpk"
import { AuthenticatedRequest, CertificateSignerResponse } from "../types"
import { CertificateExtraExtensionsError, CreateCertificateOptions, createSignedCertificate } from "../certificate"
import { Logger } from "@andrewheberle/ts-slog"
import { contentJson, OpenAPIRoute } from "chanfana"
import { z } from "zod"
import { seconds } from "itty-time"
import { env } from "cloudflare:workers"

const logger = new Logger()

export class CaPublicKeyEndpoint extends OpenAPIRoute<[AuthenticatedRequest, CFArgs]> {
    schema = {
        responses: {
            "200": {
                description: "SSH Certificate Authority Public Key",
            }
        }
    }

    async handle(request: AuthenticatedRequest, env: Env, ctx: ExecutionContext) {
        try {
            const key = parsePrivateKey(await env.PRIVATE_KEY.get())
            const pub = key.toPublic()
            pub.comment = env.ISSUER_DN

            return text(`${pub.toString("ssh")}\n`)
        } catch (err) {
            // unhandled error, so just log and throw it again
            logger.error("unhandled error", "error", err)
            throw err
        }
    }
}

export class CertificateRequestEndpoint extends OpenAPIRoute<[AuthenticatedRequest, CFArgs]> {
    schema = {
        deprecated: true,
        security: [
            {
                oidcAuth: []
            }
        ],
        request: {
            body: contentJson(z.object({
                public_key: z.string().base64(),
                identity: z.string().optional(),
                extensions: z.array(z.string()).default(env.SSH_CERTIFICATE_EXTENSIONS),
                lifetime: z.number().min(300).max(seconds(env.SSH_CERTIFICATE_LIFETIME)).default(seconds(env.SSH_CERTIFICATE_LIFETIME)),
            }))
        },
        responses: {
            "200": {
                description: "Successful certificate request for a SSH user certificate",
                ...contentJson(z.object({
                    certificate: z.string(),
                }))
            }
        }
    }

    async handle(request: AuthenticatedRequest, env: Env, ctx: ExecutionContext) {
        logger.info("handling request", "for", request.email)
        try {
            const data = await this.getValidatedData<typeof this.schema>()

            const opts: CreateCertificateOptions = {
                lifetime: data.body.lifetime,
                principals: request.principals,
                extensions: data.body.extensions as typeof env.SSH_CERTIFICATE_EXTENSIONS
            }
            const certificate = await createSignedCertificate(request.email, request.public_key, opts)
            const response: CertificateSignerResponse = {
                certificate: btoa(certificate.toString("openssh"))
            }

            return response
        } catch (err) {
            if (err instanceof CertificateExtraExtensionsError) {
                logger.error("the request included additional certificate extensions", "error", err)
                return error(400)
            }

            // unhandled error, so just log and throw it again
            logger.error("unhandled error", "error", err)
            throw err
        }
    }
}
