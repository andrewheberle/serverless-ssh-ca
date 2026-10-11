import { spawnSync } from "node:child_process"
import { writeFileSync, readFileSync, rmSync, mkdtempSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"

const Namespace = "proof-of-possession@com.github.serverless-ssh-ca.andrewheberle"

// runs ssh-keygen, throwing if it fails
const sshKeygen = (...args: string[]): string => {
    const result = spawnSync("ssh-keygen", args)
    if (result.status !== 0) {
        throw new Error(`ssh-keygen failed: ${result.stderr.toString()}`)
    }

    return result.stdout.toString()
}

/**
 * Generates a proof of possession with ssh-keygen
 *
 * @param key The key in OpenSSH format, with its public key as written by ssh-keygen -y
 */
export const generateProof = (key: { privateKey: string, publicKey: string }): string => {
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
        writeFileSync(dataFile, data, { encoding: "utf-8" })

        sshKeygen("-Y", "sign", "-f", keyFile, "-n", Namespace, dataFile)

        // read armored signature and base64 encode it
        const armoredSig = readFileSync(`${dataFile}.sig`, { encoding: "utf-8" })

        return `${data}.${Buffer.from(armoredSig).toString("base64")}`
    } finally {
        rmSync(dir, { recursive: true, force: true })
    }
}
