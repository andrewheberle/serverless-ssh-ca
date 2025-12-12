import { describe, it, expect } from "vitest"
import { HostNonce, Nonce } from "../src/nonce"
import { createSelfSignedCertificate, generatePrivateKey, identityForHost, parseSignature } from "sshpk"
import { ms } from "itty-time"

const ecdsaPrivateKey = generatePrivateKey("ecdsa")
const ed25519PrivateKey = generatePrivateKey("ed25519")

describe("Nonce", () => {
    const currentTimestamp = Date.now() * 60 * 1000
    const fingerprint = ecdsaPrivateKey.toPublic().fingerprint().toString()
    const signer = ecdsaPrivateKey.createSign("sha256")
    const format = "ecdsa-sha2-nistp256"
    signer.update(`${currentTimestamp}.${fingerprint}`)
    const signature = signer.sign().toString("ssh")

    it("should parse and verify valid nonce string without format", () => {
        const nonce = new Nonce(`${currentTimestamp}.${fingerprint}.:${signature}`)
        expect(nonce.timestamp).toBe(currentTimestamp)
        expect(nonce.matches(ecdsaPrivateKey.toPublic())).toBe(true)
        expect(nonce.verify(ecdsaPrivateKey.toPublic())).toBe(true)
    })

    it("should parse and verify valid nonce string", () => {
        const nonce = new Nonce(`${currentTimestamp}.${fingerprint}.${format}:${signature}`)
        expect(nonce.timestamp).toBe(currentTimestamp)
        expect(nonce.matches(ecdsaPrivateKey.toPublic())).toBe(true)
        expect(nonce.verify(ecdsaPrivateKey.toPublic())).toBe(true)
    })

    it("should parse nonce string with four components but ignore third", () => {
        const nonce = new Nonce(`${currentTimestamp}.${fingerprint}.third.${format}:${signature}`)
        expect(nonce.timestamp).toBe(currentTimestamp)
        expect(nonce.matches(ecdsaPrivateKey.toPublic())).toBe(true)
        expect(nonce.verify(ecdsaPrivateKey.toPublic())).toBe(true)
    })

    it("should reject bad format", () => {
        expect(() => new Nonce(`${currentTimestamp}.${fingerprint}`))
            .toThrow("invalid nonce format")
    })

    it("should reject expired timestamp", () => {
        const oldTimestamp = Date.now() - ms("6 minutes")
        expect(() => new Nonce(`${oldTimestamp}.${fingerprint}.${format}:ignored`))
            .toThrow("nonce timestamp too old")
    })

    it("should reject invalid fingerprint", () => {
        expect(() => new Nonce(`${currentTimestamp}.thisisinvalid.${format}:ignored`))
            .toThrow("nonce fingerprint was an invalid format")
    })

    it("should reject invalid signature", () => {
        expect(() => new Nonce(`${currentTimestamp}.${fingerprint}.${format}:thisisinvalid`))
            .toThrow("nonce signature could not be parsed")
    })
})

describe("HostNonce (ECDSA)", () => {
    const currentTimestamp = Date.now() * 60 * 1000

    const publicKey = ecdsaPrivateKey.toPublic()
    const fingerprint = publicKey.fingerprint().toString()
    const signer = ecdsaPrivateKey.createSign("sha256")
    const format = "ecdsa-sha2-nistp256"
    const cert = createSelfSignedCertificate(identityForHost("testhost"), ecdsaPrivateKey)
    const certFingerprint = cert.fingerprint().toString()
    signer.update(`${currentTimestamp}.${fingerprint}.${certFingerprint}`)
    const ecdsaSignature = signer.sign().toString("ssh")

    it("ecdsa should reject invalid nonce string", () => {
        expect(() => new HostNonce(`${currentTimestamp}.${fingerprint}.${format}:${ecdsaSignature}`))
            .toThrow("invalid nonce format")
    })

    it("ecdsa should parse and verify valid host nonce string without format", () => {
        const nonce = new HostNonce(`${currentTimestamp}.${fingerprint}.${certFingerprint}.${ecdsaSignature}`)
        expect(nonce.timestamp, "verify timestamp").toBe(currentTimestamp)
        expect(nonce.certificatematches(publicKey, cert), "verify certificatematches works").toBe(true)
        expect(nonce.verify(publicKey), "check verify works").toBe(true)
    })

    it("ecdsa should parse and verify valid host nonce string", () => {
        const nonce = new HostNonce(`${currentTimestamp}.${fingerprint}.${certFingerprint}.${format}:${ecdsaSignature}`)
        expect(nonce.timestamp, "verify timestamp").toBe(currentTimestamp)
        expect(nonce.certificatematches(publicKey, cert), "verify certificatematches works").toBe(true)
        expect(nonce.verify(publicKey), "check verify works").toBe(true)
    })

    it("ecdsa should reject bad format", () => {
        expect(() => new HostNonce(`${currentTimestamp}.${fingerprint}`))
            .toThrow("invalid nonce format")
    })

    it("ecdsa should reject expired timestamp", () => {
        const oldTimestamp = Date.now() - ms("6 minutes")
        expect(() => new HostNonce(`${oldTimestamp}.${fingerprint}.thisisinvalid.${format}:ignored`))
            .toThrow("nonce timestamp too old")
    })

    it("ecdsa should reject invalid fingerprint", () => {
        expect(() => new HostNonce(`${currentTimestamp}.thisisinvalid.thisisinvalid.${format}:ignored`))
            .toThrow("nonce fingerprint was an invalid format")
    })

    it("ecdsa should reject invalid signature", () => {
        expect(() => new HostNonce(`${currentTimestamp}.${fingerprint}.${certFingerprint}.${format}:thisisinvalid`))
            .toThrow("nonce signature could not be parsed")
    })
})

describe("HostNonce (ED25519)", () => {
    const currentTimestamp = Date.now() * 60 * 1000

    const publicKey = ed25519PrivateKey.toPublic()
    const fingerprint = publicKey.fingerprint().toString()
    const signer = ed25519PrivateKey.createSign("sha512")
    const format = "ssh-ed25519"
    const cert = createSelfSignedCertificate(identityForHost("testhost"), ed25519PrivateKey)
    const certFingerprint = cert.fingerprint().toString()
    signer.update(`${currentTimestamp}.${fingerprint}.${certFingerprint}`)
    const signature = signer.sign().toString("ssh")

    it("ed25519 should reject invalid nonce string", () => {
        expect(() => new HostNonce(`${currentTimestamp}.${fingerprint}.${format}:${signature}`))
            .toThrow("invalid nonce format")
    })

    it("ed25519 should parse but fail verify with valid host nonce string without format", () => {
        const nonce = new HostNonce(`${currentTimestamp}.${fingerprint}.${certFingerprint}.${signature}`)
        expect(nonce.timestamp, "verify timestamp").toBe(currentTimestamp)
        expect(nonce.certificatematches(publicKey, cert), "verify certificatematches works").toBe(true)
        expect(nonce.verify(publicKey), "check verify works").toBe(false)
    })

    it("ed25519 should parse and verify valid host nonce string", () => {
        const nonce = new HostNonce(`${currentTimestamp}.${fingerprint}.${certFingerprint}.${format}:${signature}`)
        expect(nonce.timestamp, "verify timestamp").toBe(currentTimestamp)
        expect(nonce.certificatematches(publicKey, cert), "verify certificatematches works").toBe(true)
        expect(nonce.verify(publicKey), "check verify works").toBe(true)
    })

    it("ed25519 should reject bad format", () => {
        expect(() => new HostNonce(`${currentTimestamp}.${fingerprint}`))
            .toThrow("invalid nonce format")
    })

    it("ed25519 should reject expired timestamp", () => {
        const oldTimestamp = Date.now() - ms("6 minutes")
        expect(() => new HostNonce(`${oldTimestamp}.${fingerprint}.thisisinvalid.${format}:ignored`))
            .toThrow("nonce timestamp too old")
    })

    it("ed25519 should reject invalid fingerprint", () => {
        expect(() => new HostNonce(`${currentTimestamp}.thisisinvalid.thisisinvalid.${format}:ignored`))
            .toThrow("nonce fingerprint was an invalid format")
    })

    it("ed25519 should reject invalid signature", () => {
        expect(() => new HostNonce(`${currentTimestamp}.${fingerprint}.${certFingerprint}.${format}:thisisinvalid`))
            .toThrow("nonce signature could not be parsed")
    })
})