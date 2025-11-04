import { RequestHandler, StatusError } from "itty-router"
import { CFArgs } from "./router"
import { AuthenticatedRequest, CertificateSignerPayload, LogLevelError, LogLevelInfo, LogLevelWarning } from "./types"
import { parseKey } from "sshpk"
import { seconds } from "itty-time"
import { verifyJWT } from "./verify"
import { JWSInvalid, JWTInvalid } from "jose/errors"

export const withPayload: RequestHandler<AuthenticatedRequest, CFArgs> = async (request: AuthenticatedRequest, env: Env, ctx: ExecutionContext) => {
    try {
        const payload = await request.json<CertificateSignerPayload>()

        // if an identity was provided, validate this
        if (payload.identity !== undefined) {
            console.log({ level: LogLevelInfo, message: "request included an identity token" })
            const identity = await verifyJWT(payload.identity)

            // make sure subjects match
            if (identity.payload.sub !== request.sub) {
                console.log({ level: LogLevelWarning, message: "possible token substitution as subjects for authentication and identity tokens did not match" })
                throw new StatusError(401)
            }

            // warn if both were undefined
            if (identity.payload.sub === undefined && request.sub === undefined) {
                console.log({ level: LogLevelWarning, message: "the sub claim was missing on tokens" })
            }

            // extract principals claim info from id token if set
            if (env.JWT_SSH_CERTIFICATE_PRINCIPALS_CLAIM !== undefined) {
                if (identity.payload[env.JWT_SSH_CERTIFICATE_PRINCIPALS_CLAIM] !== undefined) {
                    const p = identity.payload[env.JWT_SSH_CERTIFICATE_PRINCIPALS_CLAIM]

                    // add to request making sure its as string[]
                    request.principals = typeof p === "string" ? [p] : p

                    // replace any spaces with underscores
                    request.principals.forEach((value, index, array) => {
                        array[index] = value.replaceAll(" ", "_")
                    })

                    console.log({ level: LogLevelInfo, message: "identity token included principals", principals: request.principals })
                } else {
                    console.log({ level: LogLevelInfo, message: "no additional principals included in identity token" })
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
            console.log({ level: LogLevelError, message: "the identity token was invalid", error: err })
            throw new StatusError(400)
        } else if (err instanceof JWTInvalid) {
            console.log({ level: LogLevelError, message: "the identity token failed verification", error: err })
            throw new StatusError(401)
        } else if (err instanceof StatusError) {
            // any StatusError types should have their own logging
            throw err
        }

        // unhandled error, so just log and throw it again
        console.log({ level: LogLevelError, error: err })
        throw err
    }
}
