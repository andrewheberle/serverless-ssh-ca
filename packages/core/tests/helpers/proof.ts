import { spawnSync } from "node:child_process"
import { writeFileSync, readFileSync, rmSync, mkdtempSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"
import type { TestKey } from "../keys/types.js"
import { fingerprint } from "./ssh-keygen.js"

// the namespaces and signed data are written out here rather than taken from
// the CA, so the tests check the format the CA expects
const Namespace = "proof-of-possession@com.github.serverless-ssh-ca.andrewheberle"
const RequestNamespace = "request-proof-of-possession@com.github.serverless-ssh-ca.andrewheberle"

/**
 * Generates a proof of possession as used by the v3 API
 */
export const generateProof = (key: TestKey): string => {
    const data = `${Date.now()}.${fingerprint(key.publicKey)}`

    return `${data}.${sign(key, data, Namespace)}`
}

/**
 * Generates a proof of possession bound to a request, as used by the v4 API
 */
export const generateRequestProof = (key: TestKey, method: string, path: string, options?: { timestamp?: number, namespace?: string }): string => {
    const data = `${options?.timestamp ?? Date.now()}.${fingerprint(key.publicKey)}`
    const signature = sign(key, `${data}.${method} ${path}`, options?.namespace ?? RequestNamespace)

    // the request the proof is bound to is signed but not sent as part of it
    return `${data}.${signature}`
}

// signs data with ssh-keygen -Y sign and returns the BASE64 encoded armored signature
const sign = (key: TestKey, data: string, namespace: string): string => {
    const dir = mkdtempSync(join(tmpdir(), "ssh-proof-"))
    const keyFile = join(dir, "key")
    const dataFile = join(dir, "data")

    try {
        writeFileSync(keyFile, key.privateKey, { mode: 0o600 })
        writeFileSync(dataFile, data, { encoding: "utf-8" })

        const result = spawnSync("ssh-keygen", ["-Y", "sign", "-f", keyFile, "-n", namespace, dataFile])
        if (result.status !== 0) {
            throw new Error(`ssh-keygen failed: ${result.stderr.toString()}`)
        }

        const armoredSig = readFileSync(`${dataFile}.sig`, { encoding: "utf-8" })

        return Buffer.from(armoredSig).toString("base64")
    } finally {
        rmSync(dir, { recursive: true, force: true })
    }
}
