import { describe, it, expect } from "vitest"
import { InternalServerErrorException } from "chanfana"
import { KeyParseError } from "../src/ssh/keys.js"
import { SshCertificate } from "../src/ssh/certificate.js"
import { pub } from "./helpers/keys.js"
import { generateKey, signCertificate } from "./helpers/ssh-keygen.js"
import { RenewalProofOfPossession } from "../src/proof.js"
import { generateProof } from "./helpers/proof.js"
import type { z } from "zod"
import { getPrivateKey, getPublic, hostPrincipalIssue, refineHostCertificateRenewal, split, UnsupportedKeyError } from "../src/utils.js"
import { env, makeEnv } from "./env.js"
import { MockSecretStore } from "./helpers/secret.js"
import { key as rsaKey } from "./keys/rsa.js"
import { key as ecdsaKey } from "./keys/ecdsa.js"
import { key as ed25519Key } from "./keys/ed25519.js"

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

describe("getPrivateKey", () => {
    it("should load an ECDSA CA key", async () => {
        const key = await getPrivateKey(makeEnv({ PRIVATE_KEY: new MockSecretStore(ecdsaKey.ca().privateKey) }))
        expect(key.type).toBe("ecdsa")
    })

    it("should load an Ed25519 CA key", async () => {
        const key = await getPrivateKey(makeEnv({ PRIVATE_KEY: new MockSecretStore(ed25519Key.ca().privateKey) }))
        expect(key.type).toBe("ed25519")
    })

    it("should reject an RSA CA key", async () => {
        const result = getPrivateKey(makeEnv({ PRIVATE_KEY: new MockSecretStore(rsaKey.ca().privateKey) }))
        await expect(result).rejects.toBeInstanceOf(UnsupportedKeyError)
        await expect(result).rejects.toThrow("CA key type rsa is not supported, the CA key must be Ed25519 or ECDSA")
    })

    it("should reject a key that is not in OpenSSH format", async () => {
        const result = getPrivateKey(makeEnv({ PRIVATE_KEY: new MockSecretStore(generateKey("ecdsa", 256, ["-m", "PEM"]).privateKey) }))
        await expect(result).rejects.toBeInstanceOf(KeyParseError)
        await expect(result).rejects.toThrow("private key was not in OpenSSH format")
    })

    it("should throw KeyParseError for an invalid key", async () => {
        await expect(getPrivateKey(makeEnv({ PRIVATE_KEY: new MockSecretStore("not a key") }))).rejects.toBeInstanceOf(KeyParseError)
    })
})

describe("getPublic", () => {
    it("should reject an RSA CA key", async () => {
        await expect(getPublic(makeEnv({ PRIVATE_KEY: new MockSecretStore(rsaKey.ca().privateKey) })))
            .rejects.toBeInstanceOf(UnsupportedKeyError)
    })
})

describe("refineHostCertificateRenewal", () => {
    it("should throw a server error rather than a validation issue for an RSA CA key", async () => {
        const rsaEnv = makeEnv({ PRIVATE_KEY: new MockSecretStore(rsaKey.ca().privateKey) })
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
    const caEnv = makeEnv({ PRIVATE_KEY: new MockSecretStore(ca.privateKey) })
    const isRevoked = async (): Promise<boolean> => false

    // validity is an interval as passed to ssh-keygen -V
    const refine = async (validity: string): Promise<unknown[]> => {
        const certificate = SshCertificate.parse(signCertificate(ca, host.publicKey, { kind: "host", keyId: "host_test_host", principals: ["test_host"], validity }))
        const issues: unknown[] = []
        const ctx = { issues } as unknown as z.RefinementCtx
        await refineHostCertificateRenewal(caEnv, isRevoked, {
            certificate,
            proof: new RenewalProofOfPossession(generateProof(host)),
            public_key: pub(host),
            lifetime: 3600,
        }, ctx)
        return issues
    }

    it("should accept a certificate whose validity starts a second in the future", async () => {
        expect(await refine("+1s:+1h")).toEqual([])
    })

    it("should reject a certificate whose validity starts beyond the allowed skew", async () => {
        const issues = await refine("+1h:+2h")
        expect(issues).toMatchObject([{ message: "the provided certificate is not yet valid" }])
    })

    it("should reject an expired certificate", async () => {
        const issues = await refine("-2h:-1h")
        expect(issues).toMatchObject([{ message: "the provided certificate is expired" }])
    })
})

describe("hostPrincipalIssue", () => {
    it.each(["host", "host.example.com", "192.0.2.10", "2001:db8::1", "[host.example.com]:2222"])("should allow %j", (principal) => {
        expect(hostPrincipalIssue(principal)).toBeUndefined()
    })

    it.each(["", "*", "*.example.com", "host?", "!host", "a,b", "host name", "host\tname", "host\u0000"])("should not allow %j", (principal) => {
        expect(hostPrincipalIssue(principal)).toEqual(expect.any(String))
    })
})

describe("refineHostCertificateRenewal principals", () => {
    const ca = ecdsaKey.ca()
    const host = ecdsaKey.host()
    const caEnv = makeEnv({ PRIVATE_KEY: new MockSecretStore(ca.privateKey) })
    const isRevoked = async (): Promise<boolean> => false

    const refine = async (principals: string[]): Promise<unknown[]> => {
        const certificate = SshCertificate.parse(signCertificate(ca, host.publicKey, { kind: "host", keyId: "host_test_host", principals, validity: "-1m:+1h" }))
        const issues: unknown[] = []
        const ctx = { issues } as unknown as z.RefinementCtx
        await refineHostCertificateRenewal(caEnv, isRevoked, {
            certificate,
            proof: new RenewalProofOfPossession(generateProof(host)),
            public_key: pub(host),
            lifetime: 3600,
        }, ctx)
        return issues
    }

    it("should renew a certificate with allowed principals", async () => {
        expect(await refine(["test_host", "192.0.2.10"])).toEqual([])
    })

    it("should not renew a certificate with a wildcard principal", async () => {
        const issues = await refine(["test_host", "*.example.com"])
        expect(issues).toMatchObject([{ message: expect.stringContaining("the provided certificate cannot be renewed") }])
    })
})
