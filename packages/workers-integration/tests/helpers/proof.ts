import { spawnSync } from "node:child_process"
import { writeFileSync, readFileSync, rmSync, mkdtempSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"

const RequestNamespace = "request-proof-of-possession@com.github.serverless-ssh-ca.andrewheberle"

// runs ssh-keygen, throwing if it fails
const sshKeygen = (...args: string[]): string => {
    const result = spawnSync("ssh-keygen", args)
    if (result.status !== 0) {
        throw new Error(`ssh-keygen failed: ${result.stderr.toString()}`)
    }

    return result.stdout.toString()
}

type Key = { privateKey: string, publicKey: string }

/**
 * Generates a proof of possession with ssh-keygen bound to a request, as used
 * by the v4 API
 *
 * @param key The key in OpenSSH format, with its public key as written by ssh-keygen -y
 * @param method The HTTP method of the request
 * @param path The path of the request
 */
export const generateRequestProof = (key: Key, method: string, path: string): string => {
    // create temp dir to hold key and data files
    const dir = mkdtempSync(join(tmpdir(), "ssh-proof-"))
    const keyFile = join(dir, "key")
    const dataFile = join(dir, "data")

    try {
        writeFileSync(keyFile, key.privateKey, { mode: 0o600 })
        writeFileSync(`${keyFile}.pub`, `${key.publicKey}\n`)

        // "<bits> <fingerprint> <comment> (<type>)"
        const fingerprint = sshKeygen("-l", "-E", "sha256", "-f", `${keyFile}.pub`).split(" ")[1]
        const data = `${Date.now()}.${fingerprint}`
        // the request the proof is bound to is signed but not sent as part of the proof
        writeFileSync(dataFile, `${data}.${method} ${path}`, { encoding: "utf-8" })

        sshKeygen("-Y", "sign", "-f", keyFile, "-n", RequestNamespace, dataFile)

        // read armored signature and base64 encode it
        const armoredSig = readFileSync(`${dataFile}.sig`, { encoding: "utf-8" })

        return `${data}.${Buffer.from(armoredSig).toString("base64")}`
    } finally {
        rmSync(dir, { recursive: true, force: true })
    }
}
