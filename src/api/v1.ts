import { IRequest, IttyRouter, StatusError, text } from "itty-router";
import { CFArgs } from "../router";
import { parsePrivateKey } from "sshpk";
import { withValidJWT } from "../verify";
import { CertificateSignerResponse } from "../types";
import { CertificateExtraExtensionsError, CreateCertificateOptions, createSignedCertificate } from "../certificate";
import { withPayload } from "../payload";

export const router = IttyRouter<IRequest, CFArgs>({ base: '/api/v1' })

router
    .get("/ca", async (request, env, ctx) => {
        try {
            const key = parsePrivateKey(await env.PRIVATE_KEY.get())
            const pub = key.toPublic()
            pub.comment = env.ISSUER_DN

            return text(`${pub.toString("ssh")}\n`)
        } catch (err) {
            console.log(err)
            throw new StatusError(503)
        }
    })
    .post("/certificate", withValidJWT, withPayload, async (request, env, ctx) => {
        console.log(`Handling request for ${request.email}`)
        try {
            const opts: CreateCertificateOptions = {
                lifetime: request.lifetime,
                principals: request.principals,
                extensions: request.extensions
            }
            const certificate = await createSignedCertificate(request.email.split("@")[0], request.public_key, opts)
            const response: CertificateSignerResponse = {
                certificate: btoa(certificate.toString("openssh"))
            }

            return response
        } catch (err) {
            if (err instanceof CertificateExtraExtensionsError) {
                console.warn(err)
                throw new StatusError(400)
            }

            console.log(err)
            throw new StatusError(503)
        }
    })
