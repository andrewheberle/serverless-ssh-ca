import { error, RequestHandler } from "itty-router"
import { CFArgs } from "./router"
import { AuthenticatedRequest, CertificateSignerPayload } from "./types"
import { parseKey } from "sshpk"
import { seconds } from "itty-time"
import { verifyJWT } from "./verify"
import { JWSInvalid, JWTInvalid } from "jose/errors"
import { Logger } from "@andrewheberle/ts-slog"

const logger = new Logger()

export const withPayload: RequestHandler<AuthenticatedRequest, CFArgs> = async (request: AuthenticatedRequest, env: Env, ctx: ExecutionContext): Promise<Response | null> => {
    try {
        const payload = await request.json<CertificateSignerPayload>()

        // if an identity was provided, validate this
        if (payload.identity !== undefined) {
            logger.info("request included an identity token")
            const identity = await verifyJWT(payload.identity)

            // make sure subjects match
            if (identity.payload.sub !== request.sub) {
                logger.warn("possible token substitution as subjects for authentication and identity tokens did not match")
                return error(401)
            }

            // warn if both were undefined
            if (identity.payload.sub === undefined && request.sub === undefined) {
                logger.warn("the sub claim was missing on tokens")
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

                    logger.info("identity token included principals", "principals", request.principals)
                } else {
                    logger.info("no additional principals included in identity token")
                }
            }
        }

        // parse provided public key
        request.public_key = parseKey(atob(payload.public_key))

        // add nonce to request if present to support v2 api requirement
        if (payload.nonce !== undefined) {
            request.nonce = payload.nonce
        }

        return null
    } catch (err) {
        if (err instanceof JWSInvalid) {
            logger.error("the identity token was invalid", "error", err)
            return error(400)
        } else if (err instanceof JWTInvalid) {
            logger.error("the identity token failed verification", "error", err)
            return error(401)
        }

        // unhandled error, so log and throw it again and handle downstream
        logger.error("unhandled error", "error", err)
        throw err
    }
}
