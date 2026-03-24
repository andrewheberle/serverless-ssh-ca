import { privateKey as rsaPrivateKey, userPrivateKey as userRsaPrivateKey } from "./keys/rsa"
import { privateKey as ecdsaPrivateKey, userPrivateKey as userEcdsaPrivateKey } from "./keys/ecdsa"
import { privateKey as ed25519PrivateKey, userPrivateKey as userEd25519PrivateKey } from "./keys/ed25519"
import { describe, expect, it } from "vitest"
import { generateCertificate } from "../src/certificate"
import { seconds } from "itty-time"
import { split } from "../src/utils"
import { env } from "cloudflare:workers"

const rsaCAKey = rsaPrivateKey()
const ecdsaCAKey = ecdsaPrivateKey()
const ed25519CAKey = ed25519PrivateKey()

const userRsaKey = userRsaPrivateKey()
const userEcdsaKey = userEcdsaPrivateKey()
const userEd25519Key = userEd25519PrivateKey()

describe("generateCertificate (RSA CA)", () => {
    const email = "test@example.com"
    const useridenties: string[] = [
        "testuser",
        "group1",
        "group2",
    ]
    const now = Date.now()

    it("handle RSA user key", () => {
        expect(() => generateCertificate(email, rsaCAKey, userRsaKey.toPublic(), { lifetime: seconds("24 hours"), principals: useridenties, now: now }))
            .toThrow("Failed to parse private key")
    })

    it("handle ECDSA user key", () => {
        expect(() => generateCertificate(email, rsaCAKey, userEcdsaKey.toPublic(), { lifetime: seconds("24 hours"), principals: useridenties, now: now }))
            .toThrow("Failed to parse private key")
    })

    it("handle ED25519 user key", () => {
        expect(() => generateCertificate(email, rsaCAKey, userEd25519Key.toPublic(), { lifetime: seconds("24 hours"), principals: useridenties, now: now }))
            .toThrow("Failed to parse private key")
    })

	it("user key with less extensions", () => {
        expect(() => generateCertificate(email, rsaCAKey, userEd25519Key.toPublic(), { lifetime: seconds("24 hours"), principals: useridenties, extensions: ["permit-user-rc"], now: now }))
            .toThrow("Failed to parse private key")
    })

	it("user key with extra extensions", () => {
        expect(() => generateCertificate(email, rsaCAKey, userEd25519Key.toPublic(), { lifetime: seconds("24 hours"), principals: useridenties, extensions: ["no-touch-required"], now: now }))
		    .toThrow("Failed to parse private key")
    })
})

describe("generateCertificate (ECDSA CA)", () => {
    const email = "test@example.com"
    const useridenties: string[] = [
        "testuser",
        "group1",
        "group2",
    ]
    const now = Date.now()

    it("handle RSA user key", () => {
        const certificate = generateCertificate(email, ecdsaCAKey, userRsaKey.toPublic(), { lifetime: seconds("24 hours"), principals: useridenties, now: now })

        expect(certificate.isSignedByKey(ecdsaCAKey.toPublic())).toBe(true)
        expect(certificate.subjects.length).toBe(useridenties.length + split(env.SSH_CERTIFICATE_PRINCIPALS).length)

        // confirm serial is set as expected
        const serialValue = certificate.serial.readBigUInt64BE(0)
        expect(serialValue).toBe(BigInt(now))
    })

    it("handle ECDSA user key", () => {
        const certificate = generateCertificate(email, ecdsaCAKey, userEcdsaKey.toPublic(), { lifetime: seconds("24 hours"), principals: useridenties, now: now })

        expect(certificate.isSignedByKey(ecdsaCAKey.toPublic())).toBe(true)
        expect(certificate.subjects.length).toBe(useridenties.length + split(env.SSH_CERTIFICATE_PRINCIPALS).length)

        // confirm serial is set as expected
        const serialValue = certificate.serial.readBigUInt64BE(0)
        expect(serialValue).toBe(BigInt(now))
    })

    it("handle ED25519 user key", () => {
        const certificate = generateCertificate(email, ecdsaCAKey, userEd25519Key.toPublic(), { lifetime: seconds("24 hours"), principals: useridenties, now: now })

        expect(certificate.isSignedByKey(ecdsaCAKey.toPublic())).toBe(true)
        expect(certificate.subjects.length).toBe(useridenties.length + split(env.SSH_CERTIFICATE_PRINCIPALS).length)

        // confirm serial is set as expected
        const serialValue = certificate.serial.readBigUInt64BE(0)
        expect(serialValue).toBe(BigInt(now))
    })

	it("user key with less extensions", () => {
        const certificate = generateCertificate(email, ecdsaCAKey, userEd25519Key.toPublic(), { lifetime: seconds("24 hours"), principals: useridenties, extensions: ["permit-user-rc"], now: now })

        expect(certificate.isSignedByKey(ecdsaCAKey.toPublic())).toBe(true)
        expect(certificate.subjects.length).toBe(useridenties.length + split(env.SSH_CERTIFICATE_PRINCIPALS).length)

        // confirm serial is set as expected
        const serialValue = certificate.serial.readBigUInt64BE(0)
        expect(serialValue).toBe(BigInt(now))
    })

	it("user key with extra extensions", () => {
        expect(() => generateCertificate(email, ecdsaCAKey, userEd25519Key.toPublic(), { lifetime: seconds("24 hours"), principals: useridenties, extensions: ["no-touch-required"], now: now }))
		    .toThrow("no-touch-required is not allowed")
    })
})

describe("generateCertificate (ED25519 CA)", () => {
    const email = "test@example.com"
    const useridenties: string[] = [
        "testuser",
        "group1",
        "group2",
    ]
    const now = Date.now()

    it("handle RSA user key", () => {
        const certificate = generateCertificate(email, ed25519CAKey, userRsaKey.toPublic(), { lifetime: seconds("24 hours"), principals: useridenties, now: now })

        expect(certificate.isSignedByKey(ed25519CAKey.toPublic())).toBe(true)
        expect(certificate.subjects.length).toBe(useridenties.length + split(env.SSH_CERTIFICATE_PRINCIPALS).length)

        // confirm serial is set as expected
        const serialValue = certificate.serial.readBigUInt64BE(0)
        expect(serialValue).toBe(BigInt(now))
    })

    it("handle ECDSA user key", () => {
        const certificate = generateCertificate(email, ed25519CAKey, userEcdsaKey.toPublic(), { lifetime: seconds("24 hours"), principals: useridenties, now: now })

        expect(certificate.isSignedByKey(ed25519CAKey.toPublic())).toBe(true)
        expect(certificate.subjects.length).toBe(useridenties.length + split(env.SSH_CERTIFICATE_PRINCIPALS).length)

        // confirm serial is set as expected
        const serialValue = certificate.serial.readBigUInt64BE(0)
        expect(serialValue).toBe(BigInt(now))
    })

    it("handle ED25519 user key", () => {
        const certificate = generateCertificate(email, ed25519CAKey, userEd25519Key.toPublic(), { lifetime: seconds("24 hours"), principals: useridenties, now: now })

        expect(certificate.isSignedByKey(ed25519CAKey.toPublic())).toBe(true)
        expect(certificate.subjects.length).toBe(useridenties.length + split(env.SSH_CERTIFICATE_PRINCIPALS).length)

        // confirm serial is set as expected
        const serialValue = certificate.serial.readBigUInt64BE(0)
        expect(serialValue).toBe(BigInt(now))
    })

	it("user key with less extensions", () => {
        const certificate = generateCertificate(email, ed25519CAKey, userEd25519Key.toPublic(), { lifetime: seconds("24 hours"), principals: useridenties, extensions: ["permit-user-rc"], now: now })

        expect(certificate.isSignedByKey(ed25519CAKey.toPublic())).toBe(true)
        expect(certificate.subjects.length).toBe(useridenties.length + split(env.SSH_CERTIFICATE_PRINCIPALS).length)
        
        // confirm serial is set as expected
        const serialValue = certificate.serial.readBigUInt64BE(0)
        expect(serialValue).toBe(BigInt(now))
    })

	it("user key with extra extensions", () => {
        expect(() => generateCertificate(email, ed25519CAKey, userEd25519Key.toPublic(), { lifetime: seconds("24 hours"), principals: useridenties, extensions: ["no-touch-required"], now: now }))
		    .toThrow("no-touch-required is not allowed")
    })
})
