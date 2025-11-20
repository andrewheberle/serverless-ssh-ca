import { describe, it, expect } from "vitest"
import { Nonce } from "../src/nonce"
import { generatePrivateKey } from "sshpk"
import { ms } from "itty-time"

const privateKey = generatePrivateKey("ecdsa")

describe("Nonce", () => {
    const currentTimestamp = Date.now() * 60 * 1000
    const fingerprint = privateKey.toPublic().fingerprint().toString()
    const signer = privateKey.createSign("sha256")
    signer.update(`${currentTimestamp}.${fingerprint}`)
    const signature = signer.sign().toString("ssh")

    it("should parse valid nonce string", () => {
        const nonce = new Nonce(`${currentTimestamp}.${fingerprint}.${signature}`)
        expect(nonce.timestamp).toBe(currentTimestamp)
        expect(nonce.fingerprint.matches(privateKey.toPublic())).toBe(true)
        expect(nonce.verify(privateKey.toPublic())).toBe(true)
    })

    it("should reject bad format", () => {
        expect(() => new Nonce(`${currentTimestamp}.${fingerprint}`))
            .toThrow("invalid nonce format")
    })

    it("should reject expired timestamp", () => {
        const oldTimestamp = Date.now() - ms("6 minutes")
        expect(() => new Nonce(`${oldTimestamp}.${fingerprint}.ignored`))
            .toThrow("nonce timestamp too old")
    })

    it("should reject invalid fingerprint", () => {
        expect(() => new Nonce(`${currentTimestamp}.thisisinvalid.ignored`))
            .toThrow("nonce fingerprint was an invalid format")
    })

    it("should reject invalid signature", () => {
        expect(() => new Nonce(`${currentTimestamp}.${fingerprint}.thisisinvalid`))
            .toThrow("nonce signature could not be parsed")
    })
})