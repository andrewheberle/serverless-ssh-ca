import { spawnSync } from "node:child_process"
import { writeFileSync, readFileSync, unlinkSync, mkdtempSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { PrivateKey } from "sshpk"
import { Namespace } from "../../src/proof"

export const generateProof = (key: PrivateKey): string => {
    const timestamp = Date.now()
    const fingerprint = key.toPublic().fingerprint("sha256").toString()
    const data = `${timestamp}.${fingerprint}`

    // create temp dir to hold key and data files
    const dir = mkdtempSync(join(tmpdir(), "ssh-proof-"))
    const keyFile = join(dir, "key")
    const dataFile = join(dir, "data")
    const sigFile = `${dataFile}.sig`

    try {
        // write key and data to temp files
        writeFileSync(keyFile, key.toString("openssh"), { mode: 0o600 })
        writeFileSync(dataFile, data, { encoding: "utf-8" })

        // sign with ssh-keygen
        const result = spawnSync("ssh-keygen", [
            "-Y", "sign",
            "-f", keyFile,
            "-n", Namespace,
            dataFile,
        ])

        if (result.status !== 0) {
            throw new Error(`ssh-keygen failed: ${result.stderr.toString()}`)
        }

        // read armored signature and base64 encode it
        const armoredSig = readFileSync(sigFile, { encoding: "utf-8" })
        const base64Sig = Buffer.from(armoredSig).toString("base64")

        return `${data}.${base64Sig}`
    } finally {
        // clean up temp files
        for (const f of [keyFile, dataFile, sigFile]) {
            try { unlinkSync(f) } catch { /* ignore */ }
        }
    }
}
