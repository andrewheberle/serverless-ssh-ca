import { RequestHandler, StatusError } from "itty-router";
import { CFArgs } from "./router";
import { AuthenticatedRequest, CertificateSignerPayload } from "./types";
import { parseKey } from "sshpk";
import { seconds } from "itty-time";
import { verifyJWT } from "./verify";
import { JWSInvalid, JWTInvalid } from "jose/errors";

export const withPayload: RequestHandler<AuthenticatedRequest, CFArgs> = async (request: AuthenticatedRequest, env: Env, ctx: ExecutionContext) => {
    try {
        const payload = await request.json<CertificateSignerPayload>()

        // if an identity was provided, validate this
        if (payload.identity !== undefined) {
            console.log("Request included an identity token")
            const identity = await verifyJWT(payload.identity)

            // make sure subjects match
            if (identity.payload.sub !== request.sub) {
                console.warn("Possible token substitution as subjects for authentication and identity tokens did not match")
                throw new StatusError(401)
            }

            // warn if both were undefined
            if (identity.payload.sub === undefined && request.sub === undefined) {
                console.warn("The sub claim was missing on tokens")
            }

            // extract principals claim info from id token if set
            if (env.JWT_SSH_CERTIFICATE_PRINCIPALS_CLAIM !== undefined) {
                if (identity.payload[env.JWT_SSH_CERTIFICATE_PRINCIPALS_CLAIM] !== undefined) {
                    const p = identity.payload[env.JWT_SSH_CERTIFICATE_PRINCIPALS_CLAIM]

                    // add to request making sure its as string[]
                    request.principals = typeof p === "string" ? [p] : p
                }
            }
        }

        // parse provided public key
        request.public_key = parseKey(atob(payload.public_key))

        // lifetime defaults to env.SSH_CERTIFICATE_LIFETIME if not set
        request.lifetime = payload.lifetime !== undefined ? payload.lifetime : seconds(env.SSH_CERTIFICATE_LIFETIME)

        // set optional extensions list
        request.extensions = payload.extensions
    } catch (err) {
        if (err instanceof JWSInvalid) {
            console.warn("The identity token was invalid")
            throw new StatusError(400)
        } else if (err instanceof JWTInvalid) {
            console.warn("The identity token failed verification")
            throw new StatusError(401)
        } else if (err instanceof StatusError) {
            throw err
        }

        console.log(err)
        throw new StatusError(503)
    }
}
