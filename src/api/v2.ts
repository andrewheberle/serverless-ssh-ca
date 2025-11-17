import { Logger } from "@andrewheberle/ts-slog"
import { error, json } from "itty-router"
import { CFArgs } from "../router"
import { CertificateExtraExtensionsError, CreateCertificateOptions, createSignedCertificate } from "../certificate"
import { AuthenticatedRequest, CertificateSignerResponse } from "../types"
import { OpenAPIRoute, contentJson } from "chanfana"
import { z } from "zod"
import { env } from "cloudflare:workers"
import { seconds } from "itty-time"

const logger = new Logger()

export class CertificateRequestEndpoint extends OpenAPIRoute<[AuthenticatedRequest, CFArgs]> {
    schema = {
        security: [
            {
                oidcAuth: []
            }
        ],
        request: {
            body: contentJson(z.object({
                public_key: z.string().base64(),
                nonce: z.string(),
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

    async handle(request: AuthenticatedRequest, env: Env, ctx: ExecutionContext): Promise<Response> {
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

            return json(response)
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
