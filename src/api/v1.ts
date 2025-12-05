import { Logger } from "@andrewheberle/ts-slog"
import { contentJson, fromHono, OpenAPIRoute } from "chanfana"
import { Hono } from "hono"
import { KeyParseError, parsePrivateKey } from "sshpk"
import { AppContext } from "../router"
import z from "zod"
import { HTTPException } from "hono/http-exception"
import { CreateCertificateOptions, createSignedCertificate } from "../certificate"
import { CertificateSignerResponse } from "../types"
import { parseIdentity, split, transformAuthorizationHeader, transformPublicKey } from "../utils"
import { env } from "cloudflare:workers"
import { seconds } from "itty-time"

const logger = new Logger()

export const api = fromHono(new Hono())

export class CaPublicKeyEndpoint extends OpenAPIRoute {
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

const HeaderSchema = z.object({
    "Authorization": z.string()
        .startsWith("Bearer ")
        .transform(transformAuthorizationHeader)
        .describe("Access Token JWT from OIDC IdP")
})

class CertificateRequestEndpoint extends OpenAPIRoute {
    schema = {
        operationId: "post_CertificateRequestEndpointv1",
        deprecated: true,
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
                    identity: z.string()
                        .optional()
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
            )
        },
        responses: {
            "200": {
                description: "SSH User Certificate issued successfully",
                ...contentJson(z.object({
                    certificate: z.string(),
                }))
            },
            "400": {
                description: "The request to the endpoint was invalid",
                ...contentJson(z.object({
                    status: z.literal(400),
                    error: z.literal("Bad Request")
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

            logger.info("handling request", "for", data.headers.Authorization.email)

            const identity = await parseIdentity(data.body.identity)
            if (data.body.identity !== undefined) {
                if (identity.sub !== data.headers["Authorization"].sub) {
                    throw new HTTPException(403, { message: "possible token substitution as subjects for authentication and identity tokens did not match" })
                }
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
                        throw new HTTPException(400, { message: "the content was not valid base64 encoded data", cause: err })
                    }
        
                    // otherwise just re-throw error
                    logger.error("some error", "error", err)
                    throw err
            }
        }
    }
}

api.get("/ca", CaPublicKeyEndpoint)
api.post("/certificate", CertificateRequestEndpoint)
