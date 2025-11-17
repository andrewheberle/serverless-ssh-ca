import { error, IttyRouter, RequestHandler, text } from "itty-router"
import { CFArgs } from "../router"
import { parsePrivateKey } from "sshpk"
import { withValidJWT } from "../verify"
import { AuthenticatedRequest, CertificateSignerResponse } from "../types"
import { CertificateExtraExtensionsError, CreateCertificateOptions, createSignedCertificate } from "../certificate"
import { withPayload } from "../payload"
import { Logger } from "@andrewheberle/ts-slog"

const logger = new Logger()

export const router = IttyRouter<AuthenticatedRequest, CFArgs>({ base: '/api/v1' })

export const handleCaRoute: RequestHandler<AuthenticatedRequest, CFArgs> = async (request, env, ctx) => {
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

export const handleUserCertificateRoute: RequestHandler<AuthenticatedRequest, CFArgs> = async (request, env, ctx) => {
    logger.info("handling request", "for", request.email)
    try {
        const opts: CreateCertificateOptions = {
            lifetime: request.lifetime,
            principals: request.principals,
            extensions: request.extensions
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

router
    .get("/ca", handleCaRoute)
    .post("/certificate", withValidJWT, withPayload, handleUserCertificateRoute)
