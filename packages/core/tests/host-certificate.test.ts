import { key as rsaKey } from "./keys/rsa.js"
import { key as ecdsaKey } from "./keys/ecdsa.js"
import { key as ed25519Key } from "./keys/ed25519.js"
import { describe, expect, it } from "vitest"
import { createSignedHostCertificate } from "../src/certificate.js"
import { seconds } from "itty-time"
import { makeEnv } from "./env.js"
import type { TestKey } from "./keys/types.js"
import { fingerprint, listCertificate } from "./helpers/ssh-keygen.js"
import { MockSecretStore } from "./helpers/secret.js"
import { UnsupportedKeyError } from "../src/utils.js"
import { pub } from "./helpers/keys.js"

type Test = {
    name: string
    key: TestKey
    wantErr?: string
}

const catests: Test[] = [
    {
        name: "RSA CA",
        key: rsaKey.ca(),
        wantErr: "CA key type rsa is not supported, the CA key must be Ed25519 or ECDSA",
    },
    {
        name: "ECDSA CA",
        key: ecdsaKey.ca()
    },
    {
        name: "ED25519 CA",
        key: ed25519Key.ca()
    },
]

const hosttests: Test[] = [
    {
        name: "RSA Host Key",
        key: rsaKey.host(),
    },
    {
        name: "ECDSA Host Key",
        key: ecdsaKey.host()
    },
    {
        name: "ED25519 Host Key",
        key: ed25519Key.host()
    },
]

for (const ca of catests) {
    describe(`createSignedHostCertificate (${ca.name})`, async () => {
        const env = makeEnv({ PRIVATE_KEY: new MockSecretStore(ca.key.privateKey) })

        if (ca.wantErr !== undefined) {
            it("should reject the CA key", async () => {
                const result = createSignedHostCertificate(env, pub(ecdsaKey.host()), { principals: ["test_host"] })
                await expect(result).rejects.toBeInstanceOf(UnsupportedKeyError)
                await expect(result).rejects.toThrow(ca.wantErr)
            })
            return
        }

        for (const host of hosttests) {
            it(host.name, async () => {
                if (host.wantErr === undefined) {
                    const issued = await createSignedHostCertificate(env, pub(host.key), { principals: ["test_host"] })

                    // ssh-keygen verifies the signature
                    const certificate = listCertificate(issued.toString())
                    expect(certificate.kind).toBe("host")
                    expect(certificate.signingCa).toBe(fingerprint(ca.key.publicKey))
                    expect(certificate.publicKey).toBe(fingerprint(host.key.publicKey))
                    expect(certificate.keyId).toBe("host_test_host")
                    expect(certificate.principals).toEqual(["test_host"])
                    expect(certificate.extensions).toEqual([])
                    expect((certificate.validBefore.getTime() - certificate.validAfter.getTime()) / 1000).toBe(seconds(env.SSH_HOST_CERTIFICATE_LIFETIME))
                } else {
                    expect(async () => await createSignedHostCertificate(env, pub(host.key), { principals: ["test_host"] }))
                        .toThrow(host.wantErr)
                }
            })
        }
    })
}
