import { key as rsaKey } from "./keys/rsa"
import { key as ecdsaKey } from "./keys/ecdsa"
import { key as ed25519Key } from "./keys/ed25519"
import { describe, expect, it } from "vitest"
import { createSignedHostCertificate } from "../src/certificate"
import { seconds } from "itty-time"
import { makeEnv } from "./env"
import { Format, Identity, type PrivateKey } from "sshpk"
import { MockSecretStore } from "./helpers/secret"

type Test = {
    name: string
    key: PrivateKey
    wantErr?: string
}

const catests: Test[] = [
    {
        name: "RSA CA - will fail on Workers runtime",
        key: rsaKey.ca(),
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
        const env = makeEnv({ PRIVATE_KEY: new MockSecretStore(ca.key.toString("openssh")) })

        for (const host of hosttests) {
            it(host.name, async () => {
                if (host.wantErr === undefined) {
                    const certificate = await createSignedHostCertificate(env, host.key.toPublic(), { principals: ["test_host"] })

                    // check its signed by the CA
                    expect(certificate.isSignedByKey(ca.key.toPublic())).toBe(true)

                    // check subjects
                    expect(certificate.subjects.length).toBe(1)
                    const certificateSubjects = certificate.subjects.map((v: Identity): string => {
                        return v.toString()
                    }).join(",")
                    expect(certificateSubjects).toBe("CN=test_host")

                    // check extensions
                    const extensions = certificate.getExtensions().map((v: Format.OpenSshSignatureExt | Format.x509SignatureExt): string => {
                        // @ts-ignore: the name property does exist
                        return v.name
                    }).join(",")
                    expect(extensions).toBe("")

                    // confirm lifetime
                    const lifetime = Math.round((certificate.validUntil.getTime() - certificate.validFrom.getTime()) / 1000)
                    expect(lifetime).toBe(seconds(env.SSH_HOST_CERTIFICATE_LIFETIME))
                } else {
                    expect(async () => await createSignedHostCertificate(env, host.key.toPublic(), { principals: ["test_host"] }))
                        .toThrow(host.wantErr)
                }
            })
        }
    })
}
