import { error, IRequest, IttyRouter, StatusError, text } from "itty-router";
import { CFArgs } from "../router";
import { parsePrivateKey } from "sshpk";
import { verifyJWT } from "../verify";
import { CertificateSignerPayload, CertificateSignerResponse } from "../types";
import { createSignedCertificate } from "../certificate";

export const router = IttyRouter<IRequest, CFArgs>({ base: '/api/v1' })

router
    .get("/ca", async (request, env, ctx) => {
        try {
            const key = parsePrivateKey(await env.PRIVATE_KEY.get())
            const pub = key.toPublic()
            pub.comment = env.ISSUER_DN

            return text(pub.toString("ssh"))
        } catch (err) {
            console.log(err)
            throw new StatusError(503)
        }
    })
    .post("/certificate", verifyJWT, async (request, env, ctx) => {
        if (request.email === undefined) {
            return error(400)
        }

        try {
            const payload = await request.json<CertificateSignerPayload>()
            const certificate = await createSignedCertificate(env, request.email.split("@")[0], payload, request.principals)
            const response: CertificateSignerResponse = {
                certificate: btoa(certificate.toString("openssh"))
            }

            return response
        } catch (err) {
            console.log(err)
            throw new StatusError(503)
        }
    })
