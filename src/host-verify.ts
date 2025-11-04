// src/host-verify.ts
import { RequestHandler, StatusError } from "itty-router"
import { CFArgs } from "./router"
import { HostAdminRequest } from "./host-types"
import { verifyJWT } from "./verify"
import { JWSInvalid, JWTInvalid } from "jose/errors"

/**
 * Middleware to verify JWT and check admin group membership
 */
export const withHostAdminJWT: RequestHandler<HostAdminRequest, CFArgs> = async (
    request: HostAdminRequest, 
    env: Env, 
    ctx: ExecutionContext
) => {
    try {
        // Extract JWT from Authorization header
        const jwt = request.headers.get("Authorization")?.replace("Bearer ", "")
        if (!jwt) {
            throw new StatusError(401, "Missing authorization token")
        }
        
        // Verify JWT
        const { payload } = await verifyJWT(jwt);
        
        if (!payload.email) {
            console.error("JWT was verified but missing required email claim")
            throw new StatusError(400, "Invalid token: missing email")
        }
        
        // Check group membership if configured
        if (env.ALLOWED_HOST_ENROLL_GROUP) {
            const groups = payload.groups
            
            if (!groups) {
                console.warn(`User ${payload.email} attempted host enrollment but has no groups claim`)
                throw new StatusError(403, "Insufficient permissions: no groups")
            }
            
            // Handle both string and string[] for groups claim
            const groupArray = Array.isArray(groups) ? groups : [groups];
            
            if (!groupArray.includes(env.ALLOWED_HOST_ENROLL_GROUP)) {
                console.warn(`User ${payload.email} attempted host enrollment but not in required group`)
                throw new StatusError(403, "Insufficient permissions: not in required group")
            }
        }
        
        console.log(`Validated admin JWT for ${payload.email}`)
        
        // Add to request
        request.email = payload.email
        request.groups = Array.isArray(payload.groups) ? payload.groups : payload.groups ? [payload.groups] : undefined
        
    } catch (err) {
        if (err instanceof JWSInvalid) {
            throw new StatusError(400, "Invalid token format")
        } else if (err instanceof JWTInvalid) {
            throw new StatusError(401, "Token verification failed")
        } else if (err instanceof StatusError) {
            throw err
        }
        
        console.error("Error verifying admin JWT:", err)
        throw new StatusError(500)
    }
}
