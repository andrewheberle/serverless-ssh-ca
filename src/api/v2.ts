import { Logger } from "@andrewheberle/ts-slog"
import { error, IRequest, IttyRouter, RequestHandler } from "itty-router"
import { CFArgs } from "../router"
import { withValidJWT, withValidNonce } from "../verify"
import { withPayload } from "../payload"
import { CertificateExtraExtensionsError, CreateCertificateOptions, createSignedCertificate } from "../certificate"
import { CertificateSignerResponse } from "../types"

const logger = new Logger()

export const router = IttyRouter<IRequest, CFArgs>({ base: "/api/v2" })

export const handleUserCertificateRoute: RequestHandler<IRequest, CFArgs> = async (request, env, ctx) => {
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
    .post("/certificate", withValidJWT, withPayload, withValidNonce, handleUserCertificateRoute)