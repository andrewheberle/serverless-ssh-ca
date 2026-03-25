import { privateKey as rsaPrivateKey, userPrivateKey as userRsaPrivateKey } from "./keys/rsa"
import { privateKey as ecdsaPrivateKey, userPrivateKey as userEcdsaPrivateKey } from "./keys/ecdsa"
import { privateKey as ed25519PrivateKey, userPrivateKey as userEd25519PrivateKey } from "./keys/ed25519"
import { describe, expect, it } from "vitest"
import { generateCertificate } from "../src/certificate"
import { seconds } from "itty-time"
import { split } from "../src/utils"
import { env } from "cloudflare:workers"
import { Format, Identity, identityForUser, Key, PrivateKey } from "sshpk"

const rsaCAKey = rsaPrivateKey()
const ecdsaCAKey = ecdsaPrivateKey()
const ed25519CAKey = ed25519PrivateKey()

const userRsaKey = userRsaPrivateKey()
const userEcdsaKey = userEcdsaPrivateKey()
const userEd25519Key = userEd25519PrivateKey()

const lifetimeString = "24 hours"
const now = Date.now()

type Tests = {
    name: string
    email: string
    useridenties: string[]
    now: number
    caKey: PrivateKey
    wantErr?: string
}

const tests: Tests[] = [
    {
        name: "RSA CA",
        email: "test@example.com",
        useridenties: [
            "testuser",
            "group1",
            "group2",
        ],
        now: Date.now(),
        caKey: rsaCAKey,
        wantErr: "Failed to parse private key"
    },
    {
        name: "ECDSA CA",
        email: "test@example.com",
        useridenties: [
            "testuser",
            "group1",
            "group2",
        ],
        now: Date.now(),
        caKey: ecdsaCAKey,
    },
    {
        name: "ED25519 CA",
        email: "test@example.com",
        useridenties: [
            "testuser",
            "group1",
            "group2",
        ],
        now: Date.now(),
        caKey: ed25519CAKey,
    },
]

for (const tt of tests) {
    describe(`generateCertificate (${tt.name})`, async () => {
        if (tt.wantErr === undefined) {
            it("handle RSA user key", () => {
                const certificate = generateCertificate(tt.email, tt.caKey, userRsaKey.toPublic(), { lifetime: seconds(lifetimeString), principals: tt.useridenties, now: now })

                // check its signed by the CA
                expect(certificate.isSignedByKey(tt.caKey.toPublic())).toBe(true)

                // check subjects
                const defaultPrincipals = split(env.SSH_CERTIFICATE_PRINCIPALS)
                expect(certificate.subjects.length).toBe(tt.useridenties.length + defaultPrincipals.length)
                const certificateSubjects = certificate.subjects.map((v: Identity): string => {
                    return v.toString()
                }).join(",")
                const subjects = tt.useridenties.concat(defaultPrincipals).map((v: string): string => {
                    return identityForUser(v).toString()
                }).join(",")
                expect(certificateSubjects).toBe(subjects)

                // check extensions
                const extensions = certificate.getExtensions().map((v: Format.OpenSshSignatureExt | Format.x509SignatureExt): string => {
                    // @ts-ignore: the name property does exist
                    return v.name
                }).join(",")
                expect(extensions).toBe(env.SSH_CERTIFICATE_EXTENSIONS)

                // confirm serial is set as expected
                const serialValue = certificate.serial.readBigUInt64BE(0)
                expect(serialValue).toBe(BigInt(now))

                // confirm lifetime
                const lifetime = (certificate.validUntil.getTime() - certificate.validFrom.getTime()) / 1000
                expect(lifetime).toBe(seconds(lifetimeString))
            })

            it("handle ECDSA user key", () => {
                const certificate = generateCertificate(tt.email, tt.caKey, userEcdsaKey.toPublic(), { lifetime: seconds(lifetimeString), principals: tt.useridenties, now: now })

                // check its signed by the CA
                expect(certificate.isSignedByKey(tt.caKey.toPublic())).toBe(true)

                // check subjects
                const defaultPrincipals = split(env.SSH_CERTIFICATE_PRINCIPALS)
                expect(certificate.subjects.length).toBe(tt.useridenties.length + defaultPrincipals.length)
                const certificateSubjects = certificate.subjects.map((v: Identity): string => {
                    return v.toString()
                }).join(",")
                const subjects = tt.useridenties.concat(defaultPrincipals).map((v: string): string => {
                    return identityForUser(v).toString()
                }).join(",")
                expect(certificateSubjects).toBe(subjects)

                // check extensions
                const extensions = certificate.getExtensions().map((v: Format.OpenSshSignatureExt | Format.x509SignatureExt): string => {
                    // @ts-ignore: the name property does exist
                    return v.name
                }).join(",")
                expect(extensions).toBe(env.SSH_CERTIFICATE_EXTENSIONS)

                // confirm serial is set as expected
                const serialValue = certificate.serial.readBigUInt64BE(0)
                expect(serialValue).toBe(BigInt(now))

                // confirm lifetime
                const lifetime = (certificate.validUntil.getTime() - certificate.validFrom.getTime()) / 1000
                expect(lifetime).toBe(seconds(lifetimeString))
            })

            it("handle ED25519 user key", () => {
                const certificate = generateCertificate(tt.email, tt.caKey, userEd25519Key.toPublic(), { lifetime: seconds(lifetimeString), principals: tt.useridenties, now: now })

                // check its signed by the CA 
                expect(certificate.isSignedByKey(tt.caKey.toPublic())).toBe(true)

                // check subjects
                const defaultPrincipals = split(env.SSH_CERTIFICATE_PRINCIPALS)
                expect(certificate.subjects.length).toBe(tt.useridenties.length + defaultPrincipals.length)
                const certificateSubjects = certificate.subjects.map((v: Identity): string => {
                    return v.toString()
                }).join(",")
                const subjects = tt.useridenties.concat(defaultPrincipals).map((v: string): string => {
                    return identityForUser(v).toString()
                }).join(",")
                expect(certificateSubjects).toBe(subjects)

                // check extensions
                const extensions = certificate.getExtensions().map((v: Format.OpenSshSignatureExt | Format.x509SignatureExt): string => {
                    // @ts-ignore: the name property does exist
                    return v.name
                }).join(",")
                expect(extensions).toBe(env.SSH_CERTIFICATE_EXTENSIONS)

                // confirm serial is set as expected
                const serialValue = certificate.serial.readBigUInt64BE(0)
                expect(serialValue).toBe(BigInt(now))

                // confirm lifetime
                const lifetime = (certificate.validUntil.getTime() - certificate.validFrom.getTime()) / 1000
                expect(lifetime).toBe(seconds(lifetimeString))
            })

            it("user key with less extensions", () => {
                const certificate = generateCertificate(tt.email, tt.caKey, userEd25519Key.toPublic(), { lifetime: seconds(lifetimeString), principals: tt.useridenties, extensions: ["permit-user-rc"], now: now })

                // check its signed by the CA
                expect(certificate.isSignedByKey(tt.caKey.toPublic())).toBe(true)

                // check subjects
                const defaultPrincipals = split(env.SSH_CERTIFICATE_PRINCIPALS)
                expect(certificate.subjects.length).toBe(tt.useridenties.length + defaultPrincipals.length)
                const certificateSubjects = certificate.subjects.map((v: Identity): string => {
                    return v.toString()
                }).join(",")
                const subjects = tt.useridenties.concat(defaultPrincipals).map((v: string): string => {
                    return identityForUser(v).toString()
                }).join(",")
                expect(certificateSubjects).toBe(subjects)

                // check extensions
                const extensions = certificate.getExtensions().map((v: Format.OpenSshSignatureExt | Format.x509SignatureExt): string => {
                    // @ts-ignore: the name property does exist
                    return v.name
                }).join(",")
                expect(extensions).toBe("permit-user-rc")

                // confirm serial is set as expected
                const serialValue = certificate.serial.readBigUInt64BE(0)
                expect(serialValue).toBe(BigInt(now))

                // confirm lifetime
                const lifetime = (certificate.validUntil.getTime() - certificate.validFrom.getTime()) / 1000
                expect(lifetime).toBe(seconds(lifetimeString))
            })

            it("user key with extra extensions", () => {
                expect(() => generateCertificate(tt.email, tt.caKey, userEd25519Key.toPublic(), { lifetime: seconds(lifetimeString), principals: tt.useridenties, extensions: ["no-touch-required"], now: now }))
                    .toThrow("no-touch-required is not allowed")
            })
        } else {
            it("handle RSA user key", () => {
                expect(() => generateCertificate(tt.email, rsaCAKey, userRsaKey.toPublic(), { lifetime: seconds(lifetimeString), principals: tt.useridenties, now: now }))
                    .toThrow("Failed to parse private key")
            })

            it("handle ECDSA user key", () => {
                expect(() => generateCertificate(tt.email, rsaCAKey, userEcdsaKey.toPublic(), { lifetime: seconds(lifetimeString), principals: tt.useridenties, now: now }))
                    .toThrow("Failed to parse private key")
            })

            it("handle ED25519 user key", () => {
                expect(() => generateCertificate(tt.email, rsaCAKey, userEd25519Key.toPublic(), { lifetime: seconds(lifetimeString), principals: tt.useridenties, now: now }))
                    .toThrow("Failed to parse private key")
            })

            it("user key with less extensions", () => {
                expect(() => generateCertificate(tt.email, rsaCAKey, userEd25519Key.toPublic(), { lifetime: seconds(lifetimeString), principals: tt.useridenties, extensions: ["permit-user-rc"], now: now }))
                    .toThrow("Failed to parse private key")
            })

            it("user key with extra extensions", () => {
                expect(() => generateCertificate(tt.email, rsaCAKey, userEd25519Key.toPublic(), { lifetime: seconds(lifetimeString), principals: tt.useridenties, extensions: ["no-touch-required"], now: now }))
                    .toThrow("Failed to parse private key")
            })
        }
    })
}
