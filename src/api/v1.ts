import { error, IRequest, IttyRouter, text } from "itty-router"
import { CFArgs } from "../router"
import { parsePrivateKey } from "sshpk"
import { withValidJWT } from "../verify"
import { CertificateSignerResponse, LogLevel } from "../types"
import { CertificateExtraExtensionsError, CreateCertificateOptions, createSignedCertificate } from "../certificate"
import { withPayload } from "../payload"

export const router = IttyRouter<IRequest, CFArgs>({ base: '/api/v1' })

router
    .get("/ca", async (request, env, ctx) => {
        try {
            const key = parsePrivateKey(await env.PRIVATE_KEY.get())
            const pub = key.toPublic()
            pub.comment = env.ISSUER_DN

            return text(`${pub.toString("ssh")}\n`)
        } catch (err) {
            // unhandled error, so just log and throw it again
            console.log({ level: LogLevel.Error, message: "unhandled error", error: err })
            throw err
        }
    })
    .post("/certificate", withValidJWT, withPayload, async (request, env, ctx) => {
        console.log({ level: LogLevel.Info, message: "handling request", for: request.email })
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
                console.log({ level: LogLevel.Error, message: "the request included additional certificate extensions", error: err })
                error(400)
            }

            // unhandled error, so just log and throw it again
            console.log({ level: LogLevel.Error, message: "unhandled error", error: err })
            throw err
        }
    })
