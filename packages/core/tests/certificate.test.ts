import { key as rsaKey } from "./keys/rsa"
import { key as ecdsaKey } from "./keys/ecdsa"
import { key as ed25519Key } from "./keys/ed25519"
import { describe, expect, it } from "vitest"
import { generateCertificate, generateSerial } from "../src/certificate"
import { seconds } from "itty-time"
import { split } from "../src/utils"
import { env } from "./env"
import { Format, Identity, identityForUser, PrivateKey } from "sshpk"

const lifetimeString = "24 hours"

type Tests = {
    name: string
    email: string
    useridenties: string[]
    serial: bigint
    caKey: PrivateKey
    wantErr?: string
}

const tests: Tests[] = [
    {
        name: "RSA CA - will fail on Workers runtime",
        email: "test@example.com",
        useridenties: [
            "testuser",
            "group1",
            "group2",
        ],
        serial: generateSerial().readBigUInt64BE(0),
        caKey: rsaKey.ca(),
    },
    {
        name: "ECDSA CA",
        email: "test@example.com",
        useridenties: [
            "testuser",
            "group1",
            "group2",
        ],
        serial: generateSerial().readBigUInt64BE(0),
        caKey: ecdsaKey.ca(),
    },
    {
        name: "ED25519 CA",
        email: "test@example.com",
        useridenties: [
            "testuser",
            "group1",
            "group2",
        ],
        serial: generateSerial().readBigUInt64BE(0),
        caKey: ed25519Key.ca(),
    },
]

for (const tt of tests) {
    describe(`generateCertificate (${tt.name})`, async () => {
        if (tt.wantErr === undefined) {
            it(`${tt.name}: handle RSA user key`, () => {
                const certificate = generateCertificate(env, tt.email, tt.caKey, rsaKey.user().toPublic(), { lifetime: seconds(lifetimeString), principals: tt.useridenties, serial: tt.serial })

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
                expect(serialValue).toBe(tt.serial)

                // confirm lifetime
                const lifetime = Math.round((certificate.validUntil.getTime() - certificate.validFrom.getTime()) / 1000)
                expect(lifetime).toBe(seconds(lifetimeString))
            })

            it(`${tt.name}: handle ECDSA user key`, () => {
                const certificate = generateCertificate(env, tt.email, tt.caKey, ecdsaKey.user().toPublic(), { lifetime: seconds(lifetimeString), principals: tt.useridenties, serial: tt.serial })

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
                expect(serialValue).toBe(tt.serial)

                // confirm lifetime
                const lifetime = Math.round((certificate.validUntil.getTime() - certificate.validFrom.getTime()) / 1000)
                expect(lifetime).toBe(seconds(lifetimeString))
            })

            it(`${tt.name}: handle ED25519 user key`, () => {
                const certificate = generateCertificate(env, tt.email, tt.caKey, ed25519Key.user().toPublic(), { lifetime: seconds(lifetimeString), principals: tt.useridenties, serial: tt.serial })

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
                expect(serialValue).toBe(tt.serial)

                // confirm lifetime
                const lifetime = Math.round((certificate.validUntil.getTime() - certificate.validFrom.getTime()) / 1000)
                expect(lifetime).toBe(seconds(lifetimeString))
            })

            it(`${tt.name}: user key with less extensions`, () => {
                const certificate = generateCertificate(env, tt.email, tt.caKey, ed25519Key.user().toPublic(), { lifetime: seconds(lifetimeString), principals: tt.useridenties, extensions: ["permit-user-rc"], serial: tt.serial})

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
                expect(serialValue).toBe(tt.serial)

                // confirm lifetime
                const lifetime = Math.round((certificate.validUntil.getTime() - certificate.validFrom.getTime()) / 1000)
                expect(lifetime).toBe(seconds(lifetimeString))
            })

            it(`${tt.name}: user key with extra extensions`, () => {
                expect(() => generateCertificate(env, tt.email, tt.caKey, ed25519Key.user().toPublic(), { lifetime: seconds(lifetimeString), principals: tt.useridenties, extensions: ["no-touch-required"], serial: tt.serial }))
                    .toThrow("no-touch-required is not allowed")
            })
        } else {
            it(`${tt.name}: handle RSA user key`, () => {
                expect(() => generateCertificate(env, tt.email, rsaKey.ca(), rsaKey.user().toPublic(), { lifetime: seconds(lifetimeString), principals: tt.useridenties, serial: tt.serial }))
                    .toThrow("Failed to parse private key")
            })

            it(`${tt.name}: handle ECDSA user key`, () => {
                expect(() => generateCertificate(env, tt.email, rsaKey.ca(), ecdsaKey.user().toPublic(), { lifetime: seconds(lifetimeString), principals: tt.useridenties, serial: tt.serial }))
                    .toThrow("Failed to parse private key")
            })

            it(`${tt.name}: handle ED25519 user key`, () => {
                expect(() => generateCertificate(env, tt.email, rsaKey.ca(), ed25519Key.user().toPublic(), { lifetime: seconds(lifetimeString), principals: tt.useridenties, serial: tt.serial }))
                    .toThrow("Failed to parse private key")
            })

            it(`${tt.name}: user key with less extensions`, () => {
                expect(() => generateCertificate(env, tt.email, rsaKey.ca(), ed25519Key.user().toPublic(), { lifetime: seconds(lifetimeString), principals: tt.useridenties, extensions: ["permit-user-rc"], serial: tt.serial }))
                    .toThrow("Failed to parse private key")
            })

            it(`${tt.name}: user key with extra extensions`, () => {
                expect(() => generateCertificate(env, tt.email, rsaKey.ca(), ed25519Key.user().toPublic(), { lifetime: seconds(lifetimeString), principals: tt.useridenties, extensions: ["no-touch-required"], serial: tt.serial }))
                    .toThrow("Failed to parse private key")
            })
        }
    })
}
