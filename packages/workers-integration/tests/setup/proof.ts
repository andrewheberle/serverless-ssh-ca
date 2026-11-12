import type { TestProject } from "vitest/node"
import { generateRequestProof } from "../helpers/proof"
import { userKey } from "../keys/ecdsa"

export default async function setup(project: TestProject) {
    project.provide("testRequestProof", generateRequestProof(userKey, "POST", "/api/v4/user/certificates"))
    // a proof for another request, which must not be accepted for issuing a certificate
    project.provide("testRevokeRequestProof", generateRequestProof(userKey, "DELETE", "/api/v4/user/certificates/1234"))
}

declare module "vitest" {
    export interface ProvidedContext {
        testRequestProof: string
        testRevokeRequestProof: string
    }
}
