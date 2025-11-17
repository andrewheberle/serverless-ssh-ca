import { IRequest, IttyRouter } from "itty-router"
import { CFArgs } from "../router"
import { handleCaRoute, handleUserCertificateRoute } from "./v1"
import { withValidJWT } from "../verify"
import { withPayload } from "../payload"

export const router = IttyRouter<IRequest, CFArgs>({ base: "/api" })

router
    .get("/ca", handleCaRoute)
    .post("/certificate", withValidJWT, withPayload, handleUserCertificateRoute)
