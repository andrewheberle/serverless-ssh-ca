import type { TestProject } from "vitest/node"
import { generateProof } from "../helpers/proof"
import { userKey } from "../keys/ecdsa"

export default async function setup(project: TestProject) {
    const proof = generateProof(userKey)
    project.provide("testProof", proof)
}

declare module "vitest" {
    export interface ProvidedContext {
        testProof: string
    }
}
