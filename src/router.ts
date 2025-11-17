import { IttyRouter, error } from "itty-router"
import { CaPublicKeyEndpoint, CertificateRequestEndpoint as CertificateRequestV1Endpoint} from "./api/v1"
import { CertificateRequestEndpoint } from "./api/v2"
import { fromIttyRouter } from "chanfana"
import { AuthenticatedRequest } from "./types"
import { withValidJWT, withValidNonce } from "./verify"
import { withPayload } from "./payload"

export type CFArgs = [Env, ExecutionContext]

const router = IttyRouter<AuthenticatedRequest, CFArgs>()

export const openapi = fromIttyRouter(router)

openapi.get("/api/v1/ca", CaPublicKeyEndpoint)
openapi.post("/api/v1/certificate", withValidJWT, withPayload, CertificateRequestV1Endpoint)
openapi.post("/api/v2/certificate", withValidJWT, withPayload, withValidNonce, CertificateRequestEndpoint)

router.all("*", () => error(404))
