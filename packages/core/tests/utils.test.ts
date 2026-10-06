import { describe, it, expect } from "vitest"
import { InternalServerErrorException } from "chanfana"
import { createCertificate, identityForHost, identityFromDN, KeyParseError } from "sshpk"
import { RenewalProofOfPossession } from "../src/proof"
import { generateProof } from "./helpers/proof"
import type { z } from "zod"
import { getPrivateKey, getPublic, identityPrincipals, PrincipalsClaimError, refineHostCertificateRenewal, split, UnsupportedKeyError } from "../src/utils"
import type { CertificateRequestJWTPayload } from "../src/types"
import { env, makeEnv } from "./env"
import { MockSecretStore } from "./helpers/secret"
import { key as rsaKey } from "./keys/rsa"
import { key as ecdsaKey } from "./keys/ecdsa"
import { key as ed25519Key } from "./keys/ed25519"

describe("split", () => {
    it ("with empty string", () => {
        const result = split("")
        expect(result).toStrictEqual([])
    })

    it ("one value", () => {
        const result = split("first")
        expect(result).toStrictEqual(["first"])
    })

    it ("two values", () => {
        const result = split("first,second")
        expect(result).toStrictEqual(["first", "second"])
    })

    it ("nothing", () => {
        const result = split()
        expect(result).toStrictEqual([])
    })

    it ("undefined", () => {
        const result = split(undefined)
        expect(result).toStrictEqual([])
    })

    it ("empty array", () => {
        const result = split([])
        expect(result).toStrictEqual([])
    })

    it ("one item array", () => {
        const result = split(["first"])
        expect(result).toStrictEqual(["first"])
    })

    it ("two item array", () => {
        const result = split(["first", "second"])
        expect(result).toStrictEqual(["first", "second"])
    })
})

describe("identityPrincipals", () => {
    it ("no principals claim", () => {
        const result = identityPrincipals(env, {email: "user@example.com", sub: "user"})
        expect(result).toStrictEqual([])
    })

    it ("empty string principals claim", () => {
        const result = identityPrincipals(env, {email: "user@example.com", sub: "user", groups: ""}, "groups")
        expect(result).toStrictEqual([])
    })

    it ("empty array principals claim", () => {
        const result = identityPrincipals(env, {email: "user@example.com", sub: "user", groups: []}, "groups")
        expect(result).toStrictEqual([])
    })

    it ("principals claim as string", () => {
        const result = identityPrincipals(env, {email: "user@example.com", sub: "user", groups: "foo"}, "groups")
        expect(result).toStrictEqual(["foo"])
    })

    it ("principals claim as array", () => {
        const result = identityPrincipals(env, {email: "user@example.com", sub: "user", groups: ["foo"]}, "groups")
        expect(result).toStrictEqual(["foo"])
    })

    it ("principals claim as array with two items", () => {
        const result = identityPrincipals(env, {email: "user@example.com", sub: "user", groups: ["foo", "bar"]}, "groups")
        expect(result).toStrictEqual(["foo", "bar"])
    })

    // the payload type only allows strings, but an IdP can send any JSON value
    const payloadWithGroups = (groups: unknown): CertificateRequestJWTPayload =>
        ({email: "user@example.com", sub: "user", groups}) as unknown as CertificateRequestJWTPayload

    it ("null principals claim", () => {
        const result = identityPrincipals(env, payloadWithGroups(null), "groups")
        expect(result).toStrictEqual([])
    })

    it.each([
        ["a number", 42],
        ["an object", {foo: "bar"}],
        ["an array of numbers", [1, 2]],
    ])("principals claim as %s", (_, groups) => {
        expect(() => identityPrincipals(env, payloadWithGroups(groups), "groups"))
            .toThrow(new PrincipalsClaimError("the groups claim must be a string or an array of strings"))
    })
})

describe("getPrivateKey", () => {
    it("should load an ECDSA CA key", async () => {
        const key = await getPrivateKey(makeEnv({ PRIVATE_KEY: new MockSecretStore(ecdsaKey.ca().toString("openssh")) }))
        expect(key.type).toBe("ecdsa")
    })

    it("should load an Ed25519 CA key", async () => {
        const key = await getPrivateKey(makeEnv({ PRIVATE_KEY: new MockSecretStore(ed25519Key.ca().toString("openssh")) }))
        expect(key.type).toBe("ed25519")
    })

    it.each([
        ["OpenSSH", "openssh"],
        ["PKCS#1", "pkcs1"],
        ["PKCS#8", "pkcs8"],
    ] as const)("should reject an RSA CA key in %s format", async (_, format) => {
        const result = getPrivateKey(makeEnv({ PRIVATE_KEY: new MockSecretStore(rsaKey.ca().toString(format)) }))
        await expect(result).rejects.toBeInstanceOf(UnsupportedKeyError)
        await expect(result).rejects.toThrow("CA key type rsa is not supported, the CA key must be Ed25519 or ECDSA")
    })

    it("should throw KeyParseError for an invalid key", async () => {
        await expect(getPrivateKey(makeEnv({ PRIVATE_KEY: new MockSecretStore("not a key") }))).rejects.toBeInstanceOf(KeyParseError)
    })
})

describe("getPublic", () => {
    it("should reject an RSA CA key", async () => {
        await expect(getPublic(makeEnv({ PRIVATE_KEY: new MockSecretStore(rsaKey.ca().toString("openssh")) })))
            .rejects.toBeInstanceOf(UnsupportedKeyError)
    })
})

describe("refineHostCertificateRenewal", () => {
    it("should throw a server error rather than a validation issue for an RSA CA key", async () => {
        const rsaEnv = makeEnv({ PRIVATE_KEY: new MockSecretStore(rsaKey.ca().toString("openssh")) })
        const issues: unknown[] = []
        // the CA key is checked before any field of the request is used, so
        // neither the request nor the context need to be complete
        const val = {} as unknown as Parameters<typeof refineHostCertificateRenewal>[2]
        const ctx = { issues } as unknown as z.RefinementCtx
        const isRevoked = async (): Promise<boolean> => false

        await expect(refineHostCertificateRenewal(rsaEnv, isRevoked, val, ctx)).rejects.toBeInstanceOf(InternalServerErrorException)
        expect(issues).toEqual([])
    })
})

describe("refineHostCertificateRenewal validity period", () => {
    const ca = ecdsaKey.ca()
    const host = ecdsaKey.host()
    const caEnv = makeEnv({ PRIVATE_KEY: new MockSecretStore(ca.toString("openssh")) })
    const isRevoked = async (): Promise<boolean> => false

    const refine = async (validFrom: Date, validUntil: Date): Promise<unknown[]> => {
        const certificate = createCertificate([identityForHost("test_host")], host.toPublic(), identityFromDN(caEnv.ISSUER_DN), ca, { validFrom, validUntil })
        const issues: unknown[] = []
        const ctx = { issues } as unknown as z.RefinementCtx
        await refineHostCertificateRenewal(caEnv, isRevoked, {
            certificate,
            proof: new RenewalProofOfPossession(generateProof(host)),
            public_key: host.toPublic(),
            lifetime: 3600,
        }, ctx)
        return issues
    }

    const at = (offsetSeconds: number): Date => new Date(Date.now() + offsetSeconds * 1000)

    it("should accept a certificate whose validity starts a second in the future", async () => {
        expect(await refine(at(1), at(3600))).toEqual([])
    })

    it("should reject a certificate whose validity starts beyond the allowed skew", async () => {
        const issues = await refine(at(3600), at(7200))
        expect(issues).toMatchObject([{ message: "the provided certificate is not yet valid" }])
    })

    it("should reject an expired certificate", async () => {
        const issues = await refine(at(-7200), at(-3600))
        expect(issues).toMatchObject([{ message: "the provided certificate is expired" }])
    })
})
