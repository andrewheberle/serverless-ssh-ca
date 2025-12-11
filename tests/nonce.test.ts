import { describe, it, expect } from "vitest"
import { HostNonce, Nonce } from "../src/nonce"
import { createSelfSignedCertificate, generatePrivateKey, identityForHost } from "sshpk"
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
        expect(nonce.matches(privateKey.toPublic())).toBe(true)
        expect(nonce.verify(privateKey.toPublic())).toBe(true)
    })

    it("should parse nonce string with four components but ignore third", () => {
        const nonce = new Nonce(`${currentTimestamp}.${fingerprint}.third.${signature}`)
        expect(nonce.timestamp).toBe(currentTimestamp)
        expect(nonce.matches(privateKey.toPublic())).toBe(true)
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

describe("HostNonce", () => {
    const currentTimestamp = Date.now() * 60 * 1000
    const fingerprint = privateKey.toPublic().fingerprint().toString()
    const signer = privateKey.createSign("sha256")
    const cert = createSelfSignedCertificate(identityForHost("testhost"), privateKey)
    const certfingerprint = cert.fingerprint().toString()
    signer.update(`${currentTimestamp}.${fingerprint}.${certfingerprint}`)
    const signature = signer.sign().toString("ssh")

    it("should reject valid nonce string", () => {
        expect(() => new HostNonce(`${currentTimestamp}.${fingerprint}.${signature}`))
            .toThrow("invalid nonce format")
    })

    it("should parse valid host nonce string", () => {
        const nonce = new HostNonce(`${currentTimestamp}.${fingerprint}.${certfingerprint}.${signature}`)
        expect(nonce.timestamp, "verify timestamp").toBe(currentTimestamp)
        expect(nonce.certificatematches(privateKey.toPublic(), cert), "verify certificatematches works").toBe(true)
        expect(nonce.verify(privateKey.toPublic()), "check verify works").toBe(true)
    })

    it("should reject bad format", () => {
        expect(() => new HostNonce(`${currentTimestamp}.${fingerprint}`))
            .toThrow("invalid nonce format")
    })

    it("should reject expired timestamp", () => {
        const oldTimestamp = Date.now() - ms("6 minutes")
        expect(() => new HostNonce(`${oldTimestamp}.${fingerprint}.thisisinvalid.ignored`))
            .toThrow("nonce timestamp too old")
    })

    it("should reject invalid fingerprint", () => {
        expect(() => new HostNonce(`${currentTimestamp}.thisisinvalid.thisisinvalid.ignored`))
            .toThrow("nonce fingerprint was an invalid format")
    })

    it("should reject invalid signature", () => {
        expect(() => new HostNonce(`${currentTimestamp}.${fingerprint}.${certfingerprint}.thisisinvalid`))
            .toThrow("nonce signature could not be parsed")
    })
})