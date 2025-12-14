import { describe, it, expect } from "vitest"
import { HostNonce, Nonce } from "../src/nonce"
import { createSelfSignedCertificate, generatePrivateKey, identityForHost, parseSignature } from "sshpk"
import { ms, seconds } from "itty-time"
import { verify } from "sshsig"


const ecdsaPrivateKey = generatePrivateKey("ecdsa")
const ed25519PrivateKey = generatePrivateKey("ed25519")

type testSig = {
    name: string
    sig: string
    data: string
    from: number
    want: boolean
    wantErr?: string
}

const tests: testSig[] = [
    {
        name: "RSA key should parse and verify",
        sig: "LS0tLS1CRUdJTiBTU0ggU0lHTkFUVVJFLS0tLS0KVTFOSVUwbEhBQUFBQVFBQUFaY0FBQUFIYzNOb0xYSnpZUUFBQUFNQkFBRUFBQUdCQU1yMHJUQno3S1RydlZ3TQpNZDFkaFZnZUl3UFJIUng3OVFvWVZ1Z09COWo0ZytKYnNaWEtKRTFiWFo2MEpnYlRHb2p2T2QyV0ROcTRuQVdqCktWa2VTS1UxeUNFK29TS1pSYm9qZit3dHF0ZWVMYzVGZ0NDUXZBWFVTcnJkTEdobzU2VUw1eFNQNkx1OHFzdTYKeG51ZkZkaWJ1cGhhaUtFV2xFQTJsWnF2b2htdTdIUTBPZUFWRTZiRWNoWm5zeFBXVzErTXA0a05saEI1QkdJcgpDMFlNTkR4QnZ5N0F6RWk3K0FRR1hvaUZRTVJCK2hiSCtGZU5kQ2lVWmV0SmNQRWJwc1pqUENFRENUVFpoaFZMCmtYellxc0tEOFBOWEd2VG9rN2dWUmpTSnEyQmU0RGFMOXlNUmF5K2pjZnRvOFFNQjIwVDMzZWlHdmVuQTl2Qk0KNysyb2dISU0yTkJ6M3V5VnVmUTViYjdVTTdwZUlocE5jaWRUeUg1VWhsaHZ1NnJaaU9yWjM1T0VaaERpc3A2WQpycDBHRUZ0SUREZHBCSXg0ZzgxN0JUK3BnV00rM0E3bndUWFpaeXZ4TTU2SlFXUGJyeklHeWlyRElibkxsRCsvCmVnWFBMMlNQZVhzTlk1VDA2K0o1T3pWU3dqYzhjRlhtbndWT25XZVJQRlRLc2oxdExRQUFBQVJtYVd4bEFBQUEKQUFBQUFBWnphR0UxTVRJQUFBR1VBQUFBREhKellTMXphR0V5TFRVeE1nQUFBWUNZU09WdWhNa1BHNGNZN3lqTgpWTEZvc0hHRFR1SENqUWluMk9BcUhDWjR5R2NxbEo3WUJ1YVpqVWU3RWRSM0RENU43bFgyc2JnZGhBTlV2NkdBCkE5VWFGTHJlWjVORmhMSlhDbk1RbkdpTEZKSEViR0taZnNvUVA0Y1cvSDdXSHFnWUFFbUtwYUdmdm9iNHRDR1oKZ1RJWUZEWVVrdE9qd3p3UEFpNlhRV0VIZW9XQ3YwWDVpSjBMd0xUZVQ0WE9MWXFNQmlQNzlOdFN3L2pBUlZFaAprTEppa05xc2tMT2paaXBXR2xmcTZBQlg4SFBsYjVnSFBDaGJ5TElmd3lhRFd2a0Zja1d5V1BNZk43U1pQWG04ClpPTGwwZGpvY213RGVpeVdYcWFHTG9JWFhNN01SQWoyRmZIeGpITWtsS0FYWFlCTjMvcktMR2xQSEdQeXR4UnIKMi85OTFFd2pId3hlaVlrVFVTT0ZzVW1PU2hBQW9tY3NuclFBWmYvOVpwNEI0M0tHVnlUWHJZd1JRYlprVU52SQpSZTg1NkZaYlRwaVFmMEthRUpGditlWEtEeDJ4a29qMUkyLzRMMitYZ1h4VEl4SG9oOE5ITll5dmw3WmhzQVlBCjVTVlpaV01Yd2hDenNiMlpucHZCTXR4VFovZk1CNWNWRDQ3OXlsa0RoYXl6YVlzPQotLS0tLUVORCBTU0ggU0lHTkFUVVJFLS0tLS0K",
        data: "1765696780805.SHA256:pKEDCHTFD39a8fmusevX8Hob8p9sZVERd8yqGyLpR/A",
        from: 1765696780000,
        want: true
    },
    {
        name: "ECDSA key should parse and verify",
        sig: "LS0tLS1CRUdJTiBTU0ggU0lHTkFUVVJFLS0tLS0KVTFOSVUwbEhBQUFBQVFBQUFHZ0FBQUFUWldOa2MyRXRjMmhoTWkxdWFYTjBjREkxTmdBQUFBaHVhWE4wY0RJMQpOZ0FBQUVFRUR6Ymk4OE10alBYSDFCb1JURU9HaS96aEc4QnhQNVZUUW5OQkFNMGZtMExtekErUUZkUlNVYVRFCkdNN2l0QjhINmZNZFAydlAxcElQcGUyOWVLQkJZd0FBQUFSbWFXeGxBQUFBQUFBQUFBWnphR0UxTVRJQUFBQmsKQUFBQUUyVmpaSE5oTFhOb1lUSXRibWx6ZEhBeU5UWUFBQUJKQUFBQUlHdmZVZGNDQkRXa3ZwL0ZHS3NkakgrRQpKZzZXN0EvWUJVZng2Z0srQ01raEFBQUFJUUQxOFd5cDNZejZ0eXNvdllXbEJHTXprRnlYbFRrSHM5blVVRXJqCkczNWVPQT09Ci0tLS0tRU5EIFNTSCBTSUdOQVRVUkUtLS0tLQo=",
        data: "1765696780805.SHA256:79mq0wtpQMTvS4+Of8VzLN0qmYWNUyTXYmqKwhEgSLs",
        from: 1765696780000,
        want: true
    },
    {
        name: "ED25519 key should parse and verify",
        sig: "LS0tLS1CRUdJTiBTU0ggU0lHTkFUVVJFLS0tLS0KVTFOSVUwbEhBQUFBQVFBQUFETUFBQUFMYzNOb0xXVmtNalUxTVRrQUFBQWdselE4SWpOeHVLMG0wOGdBcHdUUgpMUkVxUlFOSnVYZGRMek1OWHh2OUZ3WUFBQUFFWm1sc1pRQUFBQUFBQUFBR2MyaGhOVEV5QUFBQVV3QUFBQXR6CmMyZ3RaV1F5TlRVeE9RQUFBRUFRd0RKRWowNzRnekYyT2k4NkRUbllGV1BmZGc1aVQxWnRTaXoxdWYxQ0k1anAKVVVORU56b09iVmJmNjZsRlFac3hBRS9OMm5yWXJjTTQrQWNMQm80TgotLS0tLUVORCBTU0ggU0lHTkFUVVJFLS0tLS0K",
        data: "1765696780805.SHA256:4A33TPWJZ8trpUhhn0mpK1wISFzVGhWlWShoGylLUbg",
        from: 1765696780000,
        want: true
    },
    {
        name: "should error due to old timestamp",
        sig: "LS0tLS1CRUdJTiBTU0ggU0lHTkFUVVJFLS0tLS0KVTFOSVUwbEhBQUFBQVFBQUFETUFBQUFMYzNOb0xXVmtNalUxTVRrQUFBQWdselE4SWpOeHVLMG0wOGdBcHdUUgpMUkVxUlFOSnVYZGRMek1OWHh2OUZ3WUFBQUFFWm1sc1pRQUFBQUFBQUFBR2MyaGhOVEV5QUFBQVV3QUFBQXR6CmMyZ3RaV1F5TlRVeE9RQUFBRUFRd0RKRWowNzRnekYyT2k4NkRUbllGV1BmZGc1aVQxWnRTaXoxdWYxQ0k1anAKVVVORU56b09iVmJmNjZsRlFac3hBRS9OMm5yWXJjTTQrQWNMQm80TgotLS0tLUVORCBTU0ggU0lHTkFUVVJFLS0tLS0K",
        data: "1765696780805.SHA256:4A33TPWJZ8trpUhhn0mpK1wISFzVGhWlWShoGylLUbg",
        from: 1765699990000,
        wantErr: "nonce timestamp too old",
        want: false
    },
    {
        name: "should error due to bad timestamp",
        sig: "LS0tLS1CRUdJTiBTU0ggU0lHTkFUVVJFLS0tLS0KVTFOSVUwbEhBQUFBQVFBQUFETUFBQUFMYzNOb0xXVmtNalUxTVRrQUFBQWdselE4SWpOeHVLMG0wOGdBcHdUUgpMUkVxUlFOSnVYZGRMek1OWHh2OUZ3WUFBQUFFWm1sc1pRQUFBQUFBQUFBR2MyaGhOVEV5QUFBQVV3QUFBQXR6CmMyZ3RaV1F5TlRVeE9RQUFBRUFRd0RKRWowNzRnekYyT2k4NkRUbllGV1BmZGc1aVQxWnRTaXoxdWYxQ0k1anAKVVVORU56b09iVmJmNjZsRlFac3hBRS9OMm5yWXJjTTQrQWNMQm80TgotLS0tLUVORCBTU0ggU0lHTkFUVVJFLS0tLS0K",
        data: "invalid.SHA256:4A33TPWJZ8trpUhhn0mpK1wISFzVGhWlWShoGylLUbg",
        from: 1765696780000,
        wantErr: "timestamp was not a number",
        want: true
    },
    {
        name: "should error due to extra data",
        sig: "LS0tLS1CRUdJTiBTU0ggU0lHTkFUVVJFLS0tLS0KVTFOSVUwbEhBQUFBQVFBQUFETUFBQUFMYzNOb0xXVmtNalUxTVRrQUFBQWdselE4SWpOeHVLMG0wOGdBcHdUUgpMUkVxUlFOSnVYZGRMek1OWHh2OUZ3WUFBQUFFWm1sc1pRQUFBQUFBQUFBR2MyaGhOVEV5QUFBQVV3QUFBQXR6CmMyZ3RaV1F5TlRVeE9RQUFBRUFRd0RKRWowNzRnekYyT2k4NkRUbllGV1BmZGc1aVQxWnRTaXoxdWYxQ0k1anAKVVVORU56b09iVmJmNjZsRlFac3hBRS9OMm5yWXJjTTQrQWNMQm80TgotLS0tLUVORCBTU0ggU0lHTkFUVVJFLS0tLS0K",
        data: "1765696780805.SHA256:4A33TPWJZ8trpUhhn0mpK1wISFzVGhWlWShoGylLUbg.extra",
        from: 1765696780000,
        wantErr: "invalid nonce format",
        want: true
    },
    {
        name: "should error due to invalid fingerprint",
        sig: "LS0tLS1CRUdJTiBTU0ggU0lHTkFUVVJFLS0tLS0KVTFOSVUwbEhBQUFBQVFBQUFETUFBQUFMYzNOb0xXVmtNalUxTVRrQUFBQWdselE4SWpOeHVLMG0wOGdBcHdUUgpMUkVxUlFOSnVYZGRMek1OWHh2OUZ3WUFBQUFFWm1sc1pRQUFBQUFBQUFBR2MyaGhOVEV5QUFBQVV3QUFBQXR6CmMyZ3RaV1F5TlRVeE9RQUFBRUFRd0RKRWowNzRnekYyT2k4NkRUbllGV1BmZGc1aVQxWnRTaXoxdWYxQ0k1anAKVVVORU56b09iVmJmNjZsRlFac3hBRS9OMm5yWXJjTTQrQWNMQm80TgotLS0tLUVORCBTU0ggU0lHTkFUVVJFLS0tLS0K",
        data: "1765696780805.invalid",
        from: 1765696780000,
        wantErr: "nonce fingerprint was an invalid format",
        want: true
    },
    {
        name: "should fail verify due to bad signature",
        sig: "invalid",
        data: "1765696780805.SHA256:4A33TPWJZ8trpUhhn0mpK1wISFzVGhWlWShoGylLUbg",
        from: 1765696780000,
        want: false
    },
]

describe("Nonce", async () => {
    const timestamp = 1765696780805

    for (const tt of tests) {
        it(tt.name, async () => {
            if (tt.wantErr !== undefined) {
                expect(() => new Nonce(`${tt.data}.${tt.sig}`, tt.from))
                    .toThrow(tt.wantErr)
            } else {
                const nonce = new Nonce(`${tt.data}.${tt.sig}`, tt.from)

                expect(nonce.timestamp).toBe(timestamp)
                expect(await nonce.verify()).toBe(tt.want)
            }
        })
    }

})

/*

    it("should parse valid nonce string (3072)", () => {
        const fingerprint = "SHA256:FOxGPnU9vFJdsalapjmky/1YTz2dW67ekrnKGbmCRxI"
        const signature = "ssh-rsa:ck33EURdkNXw39wLgmEGfX01WPJyo4EYzz3bGNQjXvq4tT14x80ni396iIlb3hTejzJ/sNh/c1OG5RM6xnJg9pvJ9dPffhJK0rpnNJm9SpPH4G5z35cSfuG83bpBQqKFxapxqt8gqQG5grzkKjjIKhOYjcH75SD29zZzuFTzh41ymWTQx60THEBUWyBhOStfgRo4Y4r+4ZAGD9QY9U9O6P1QT5/j+8SPGsXQn6zj4WLuGCGX4RptoGg7SIm5t+0qpt34SEFWisaTVpHSkzrBtigtuLR7U2GqeBptLqvv9CzqChn5BQ9rFcpcw35s0HjDf37FhtRz/P43jSX7wVV8sjSH0ZOuiWjb5v7jsNr1GVyN1QYHoDmpz4KAHg0qQpoJk/9kt8hi0gJOELP9RXSKw/7qQosKf1H9pyQkSQXXzJbYzwK3cQYeiW7FJ/3bF8hbY4y4jYS1pZipr51UjHg7ZBSrKfUelL/MDSrYpCYJtePS0MzOaj59whzCoNdI2w7g"

        const nonce = new Nonce(`${currentTimestamp}.${fingerprint}.${signature}`)
        expect(nonce.timestamp).toBe(currentTimestamp)
    })

    it("should parse valid nonce string (2048)", () => {
        const fingerprint = "SHA256:l/2kIYE212dSFYdIlOcY0PPu3GisIyXQoDQ0n+jOqGk"
        const signature = "ssh-rsa:ZfUv1chVvW4IfhUGzhSJVVNP+NB3GaHRS7PU+rlEkYcoEQq1gCxQXMbUnqfpJ6stxOPmk6zRZ8EEvT8UErFpmxpeK6Ql8TZIwxrkqcKko9YpFt1w1qadyX2/+FJkA1GWnpGSOEBuV5A32hOxih+Sfh+sbv4coZLP9C+RKbsQe9SMkVgyb5jJQCCHnxjDzbLQHCAJ4H661tKfTCslrWGyRm5fth8gGkppnXNsE6mBosNW3Ro3Kqi9YHdEc5LLCtRuloZ5IFh+H2C8B7rDWK/0IGUT1HlfTxt3Uzux39ZIvq5Mud0T87ZD6piZ2p8UxrtxoqjmiwrNW1PSx9jWbMD2rw=="

        const nonce = new Nonce(`${currentTimestamp}.${fingerprint}.${signature}`)
        expect(nonce.timestamp).toBe(currentTimestamp)
    })
})

describe("Nonce (ED25515) - from Go", () => {
    const currentTimestamp = Date.now() * 60 * 1000
    const fingerprint = "SHA256:VGGFNWLZdgoi9tokNdReFIv2I1SRVK3dgQMttmDyPyQ"
    const signature = "ssh-ed25519:6hYTpUI16hmIb2uXpKOhquMPha3R9t80UoIT2EYu4edEs3q05HdLdE0zl2hfi4v1p7XA3AvnvLP1+JsFbVdACw=="

    it("should parse valid nonce string", () => {
        const nonce = new Nonce(`${currentTimestamp}.${fingerprint}.${signature}`)
        expect(nonce.timestamp).toBe(currentTimestamp)
    })
})

describe("Nonce (ECDSA) - from Go", () => {
    const currentTimestamp = Date.now() * 60 * 1000
    const fingerprint = "SHA256:EHgBxfzTTXAE3akdhOU4kyukO7jD4VjaG2GdqjHtfhc"
    const signature = "ecdsa-sha2-nistp256:AAAAIDn6RAxHJhTTpvu3dNIXxRqJG6ApXTsBQlYbyILxZtHCAAAAIClQTBoiU4coDX5CFDSngL5PA610WZ50CRVf8cmpNe2t"

    it("should parse valid nonce string", () => {
        const nonce = new Nonce(`${currentTimestamp}.${fingerprint}.${signature}`)
        expect(nonce.timestamp).toBe(currentTimestamp)
    })
})

describe("Nonce (ECDSA)", () => {
    const currentTimestamp = Date.now() * 60 * 1000
    const fingerprint = ecdsaPrivateKey.toPublic().fingerprint().toString()
    const signer = ecdsaPrivateKey.createSign("sha256")
    const format = "ecdsa-sha2-nistp256"
    signer.update(`${currentTimestamp}.${fingerprint}`)
    const signature = signer.sign().toString("ssh")

    it("should parse and verify valid nonce string without format", () => {
        const nonce = new Nonce(`${currentTimestamp}.${fingerprint}.${signature}`)
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
    signer.update(`${currentTimestamp}.${fingerprint}`)
    const ecdsaSignature = signer.sign().toString("ssh")

    it("ecdsa should parse and verify valid host nonce string without format", () => {
        const nonce = new HostNonce(`${currentTimestamp}.${fingerprint}.${ecdsaSignature}`)
        expect(nonce.timestamp, "verify timestamp").toBe(currentTimestamp)
        expect(nonce.matches(publicKey, cert.subjectKey), "verify matches works").toBe(true)
        expect(nonce.verify(publicKey), "check verify works").toBe(true)
    })

    it("ecdsa should parse and verify valid host nonce string", () => {
        const nonce = new HostNonce(`${currentTimestamp}.${fingerprint}.${format}:${ecdsaSignature}`)
        expect(nonce.timestamp, "verify timestamp").toBe(currentTimestamp)
        expect(nonce.matches(publicKey, cert.subjectKey), "verify matches works").toBe(true)
        expect(nonce.verify(publicKey), "check verify works").toBe(true)
    })

    it("ecdsa should reject bad format", () => {
        expect(() => new HostNonce(`${currentTimestamp}.${fingerprint}`))
            .toThrow("invalid nonce format")
    })

    it("ecdsa should reject expired timestamp", () => {
        const oldTimestamp = Date.now() - ms("6 minutes")
        expect(() => new HostNonce(`${oldTimestamp}.${fingerprint}.${format}:ignored`))
            .toThrow("nonce timestamp too old")
    })

    it("ecdsa should reject invalid fingerprint", () => {
        expect(() => new HostNonce(`${currentTimestamp}.thisisinvalid.${format}:ignored`))
            .toThrow("nonce fingerprint was an invalid format")
    })

    it("ecdsa should reject invalid signature", () => {
        expect(() => new HostNonce(`${currentTimestamp}.${fingerprint}.${format}:thisisinvalid`))
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
    console.log(ed25519PrivateKey.toString("openssh"))
    console.log(cert.toString("openssh"))
    const certFingerprint = cert.fingerprint().toString()
    console.log(certFingerprint)
    signer.update(`${currentTimestamp}.${fingerprint}`)
    const signature = signer.sign().toString("ssh")

    it("ed25519 should parse but fail verify with valid host nonce string without format", () => {
        const nonce = new HostNonce(`${currentTimestamp}.${fingerprint}.${signature}`)
        expect(nonce.timestamp, "verify timestamp").toBe(currentTimestamp)
        expect(nonce.matches(publicKey, cert.subjectKey), "verify matches works").toBe(true)
        expect(nonce.verify(publicKey), "check verify works").toBe(false)
    })

    it("ed25519 should parse and verify valid host nonce string", () => {
        const nonce = new HostNonce(`${currentTimestamp}.${fingerprint}.${format}:${signature}`)
        expect(nonce.timestamp, "verify timestamp").toBe(currentTimestamp)
        expect(nonce.matches(publicKey, cert.subjectKey), "verify matches works").toBe(true)
        expect(nonce.verify(publicKey), "check verify works").toBe(true)
    })

    it("ed25519 should parse but failt to verify valid host nonce string when not passed cert", () => {
        const nonce = new HostNonce(`${currentTimestamp}.${fingerprint}.${format}:${signature}`)
        expect(nonce.timestamp, "verify timestamp").toBe(currentTimestamp)
        expect(nonce.matches(publicKey), "verify matches fails works").toBe(false)
        expect(nonce.verify(publicKey), "check verify works").toBe(true)
    })

    it("ed25519 should reject bad format", () => {
        expect(() => new HostNonce(`${currentTimestamp}.${fingerprint}`))
            .toThrow("invalid nonce format")
    })

    it("ed25519 should reject expired timestamp", () => {
        const oldTimestamp = Date.now() - ms("6 minutes")
        expect(() => new HostNonce(`${oldTimestamp}.${fingerprint}.${format}:ignored`))
            .toThrow("nonce timestamp too old")
    })

    it("ed25519 should reject invalid fingerprint", () => {
        expect(() => new HostNonce(`${currentTimestamp}.thisisinvalid.${format}:ignored`))
            .toThrow("nonce fingerprint was an invalid format")
    })

    it("ed25519 should reject invalid signature", () => {
        expect(() => new HostNonce(`${currentTimestamp}.${fingerprint}.${format}:thisisinvalid`))
            .toThrow("nonce signature could not be parsed")
    })
})
    */