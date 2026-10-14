import { describe, it, expect } from "vitest"
import { KeyParseError } from "../src/ssh/keys.js"
import { generateKey } from "./helpers/ssh-keygen.js"
import { getPrivateKey, getPublic, hostPrincipalIssue, split, UnsupportedKeyError } from "../src/utils.js"
import { makeEnv } from "./env.js"
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

describe("hostPrincipalIssue", () => {
    it.each(["host", "host.example.com", "192.0.2.10", "2001:db8::1", "[host.example.com]:2222"])("should allow %j", (principal) => {
        expect(hostPrincipalIssue(principal)).toBeUndefined()
    })

    it.each(["", "*", "*.example.com", "host?", "!host", "a,b", "host name", "host\tname", "host\u0000"])("should not allow %j", (principal) => {
        expect(hostPrincipalIssue(principal)).toEqual(expect.any(String))
    })
})
