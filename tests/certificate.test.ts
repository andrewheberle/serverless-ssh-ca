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

describe("generateCertificate", () => {
    const email = "test@example.com"
    const useridenties: string[] = [
        "testuser",
        "group1",
        "group2",
    ]

    /* it("handle RSA user key with RSA CA key", () => {
        const certificate = generateCertificate(email, rsaCAKey, userRsaKey.toPublic(), seconds("24 hours"), useridenties)

        expect(certificate.isSignedByKey(rsaCAKey.toPublic())).toBe(true)
        expect(certificate.subjects.length).toBe(useridenties.length + split(env.SSH_CERTIFICATE_PRINCIPALS).length)
    }) */

    it("handle RSA user key with ECDSA CA key", () => {
        const certificate = generateCertificate(email, ecdsaCAKey, userRsaKey.toPublic(), seconds("24 hours"), useridenties)

        expect(certificate.isSignedByKey(ecdsaCAKey.toPublic())).toBe(true)
        expect(certificate.subjects.length).toBe(useridenties.length + split(env.SSH_CERTIFICATE_PRINCIPALS).length)
    })

    it("handle RSA user key with ED25519 CA key", () => {
        const certificate = generateCertificate(email, ed25519CAKey, userRsaKey.toPublic(), seconds("24 hours"), useridenties)

        expect(certificate.isSignedByKey(ed25519CAKey.toPublic())).toBe(true)
        expect(certificate.subjects.length).toBe(useridenties.length + split(env.SSH_CERTIFICATE_PRINCIPALS).length)
    })

    /* it("handle ECDSA user key with RSA CA key", () => {
        const certificate = generateCertificate(email, rsaCAKey, userEcdsaKey.toPublic(), seconds("24 hours"), useridenties)

        expect(certificate.isSignedByKey(rsaCAKey.toPublic())).toBe(true)
        expect(certificate.subjects.length).toBe(useridenties.length + split(env.SSH_CERTIFICATE_PRINCIPALS).length)
    }) */

    it("handle ECDSA user key with ECDSA CA key", () => {
        const certificate = generateCertificate(email, ecdsaCAKey, userEcdsaKey.toPublic(), seconds("24 hours"), useridenties)

        expect(certificate.isSignedByKey(ecdsaCAKey.toPublic())).toBe(true)
        expect(certificate.subjects.length).toBe(useridenties.length + split(env.SSH_CERTIFICATE_PRINCIPALS).length)
    })

    it("handle ECDSA user key with ED25519 CA key", () => {
        const certificate = generateCertificate(email, ed25519CAKey, userEcdsaKey.toPublic(), seconds("24 hours"), useridenties)

        expect(certificate.isSignedByKey(ed25519CAKey.toPublic())).toBe(true)
        expect(certificate.subjects.length).toBe(useridenties.length + split(env.SSH_CERTIFICATE_PRINCIPALS).length)
    })

    /* it("handle ED25519 user key with RSA CA key", () => {
        const certificate = generateCertificate(email, rsaCAKey, userEd25519Key.toPublic(), seconds("24 hours"), useridenties)

        expect(certificate.isSignedByKey(rsaCAKey.toPublic())).toBe(true)
        expect(certificate.subjects.length).toBe(useridenties.length + split(env.SSH_CERTIFICATE_PRINCIPALS).length)
    }) */

    it("handle ED25519 user key with ECDSA CA key", () => {
        const certificate = generateCertificate(email, ecdsaCAKey, userEd25519Key.toPublic(), seconds("24 hours"), useridenties)

        expect(certificate.isSignedByKey(ecdsaCAKey.toPublic())).toBe(true)
        expect(certificate.subjects.length).toBe(useridenties.length + split(env.SSH_CERTIFICATE_PRINCIPALS).length)
    })

    it("handle ED25519 user key with ED25519 CA key", () => {
        const certificate = generateCertificate(email, ed25519CAKey, userEd25519Key.toPublic(), seconds("24 hours"), useridenties)

        expect(certificate.isSignedByKey(ed25519CAKey.toPublic())).toBe(true)
        expect(certificate.subjects.length).toBe(useridenties.length + split(env.SSH_CERTIFICATE_PRINCIPALS).length)
    })
})