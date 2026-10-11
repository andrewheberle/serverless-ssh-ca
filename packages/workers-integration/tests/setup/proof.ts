import type { TestProject } from "vitest/node"
import { generateProof, generateRequestProof } from "../helpers/proof"
import { userKey } from "../keys/ecdsa"

export default async function setup(project: TestProject) {
    const proof = generateProof(userKey)
    project.provide("testProof", proof)
    project.provide("testRequestProof", generateRequestProof(userKey, "POST", "/api/v4/user/certificates"))
}

declare module "vitest" {
    export interface ProvidedContext {
        testProof: string
        testRequestProof: string
    }
}
