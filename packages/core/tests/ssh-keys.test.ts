import { spawnSync } from "node:child_process"
import { generateKeyPairSync } from "node:crypto"
import { copyFileSync, mkdtempSync, readFileSync, rmSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { afterAll, beforeAll, describe, expect, it } from "vitest"
import { KeyParseError, parsePrivateKey, PublicKey, UnsupportedKeyError, type PrivateKey } from "../src/ssh/keys.js"
import { CertificateParseError, SshCertificate } from "../src/ssh/certificate.js"
import { KRLBuilder } from "../src/krl.js"
import { verifySignature } from "./helpers/ssh-keygen.js"

// keys and certificates are created with ssh-keygen, so the parsers are
// checked against what OpenSSH itself writes

let dir: string
let created = 0

const sshKeygen = (...args: string[]): string => {
	const result = spawnSync("ssh-keygen", args)
	if (result.status !== 0) {
		throw new Error(`ssh-keygen ${args.join(" ")} failed: ${result.stderr.toString()}`)
	}

	return result.stdout.toString()
}

// creates a key with ssh-keygen, returning the path to its private key
const createKey = (name: string, type: string[], options: string[] = []): string => {
	// keys are given unique file names as ssh-keygen will not overwrite a file
	const file = join(dir, `${created++}-${name}`)
	sshKeygen("-q", ...type, "-N", "", "-C", `${name}@example.com`, ...options, "-f", file)

	return file
}

const keyTypes: [string, string[]][] = [
	["Ed25519", ["-t", "ed25519"]],
	["ECDSA nistp256", ["-t", "ecdsa", "-b", "256"]],
	["ECDSA nistp384", ["-t", "ecdsa", "-b", "384"]],
	["ECDSA nistp521", ["-t", "ecdsa", "-b", "521"]],
]

beforeAll(() => {
	dir = mkdtempSync(join(tmpdir(), "ssh-keys-"))
})

afterAll(() => {
	rmSync(dir, { recursive: true, force: true })
})

describe("parsePrivateKey", () => {
	it.each(keyTypes)("should parse an %s key", async (name, type) => {
		const file = createKey(name.replace(/\s/g, "-"), type)
		const key = await parsePrivateKey(readFileSync(file, "utf8"))
		const expected = PublicKey.parse(readFileSync(`${file}.pub`, "utf8"))

		expect(key.publicKey.equals(expected)).toBe(true)
		expect(key.publicKey.comment).toBe(`${name.replace(/\s/g, "-")}@example.com`)
		expect(key.type).toBe(name.startsWith("Ed25519") ? "ed25519" : "ecdsa")
	})

	it("should reject an RSA key", async () => {
		const file = createKey("rsa", ["-t", "rsa", "-b", "2048"])

		await expect(parsePrivateKey(readFileSync(file, "utf8"))).rejects.toThrow(UnsupportedKeyError)
		await expect(parsePrivateKey(readFileSync(file, "utf8"))).rejects.toThrow("CA key type rsa is not supported, the CA key must be Ed25519 or ECDSA")
	})

	it("should reject an encrypted key", async () => {
		const file = join(dir, "encrypted")
		sshKeygen("-q", "-t", "ed25519", "-N", "a passphrase", "-f", file)

		await expect(parsePrivateKey(readFileSync(file, "utf8"))).rejects.toThrow(KeyParseError)
		await expect(parsePrivateKey(readFileSync(file, "utf8"))).rejects.toThrow("encrypted private keys are not supported")
	})

	it("should reject a key with mismatched check values", async () => {
		const file = createKey("corrupt", ["-t", "ed25519"])
		const text = readFileSync(file, "utf8")
		const body = Buffer.from(text.replace(/-----[^-]+-----/g, "").replace(/\s+/g, ""), "base64")
		// the check values are the first 8 bytes of the private section,
		// which follows its length
		const corrupted = Buffer.from(body)
		const offset = findPrivateSection(body) + 4
		corrupted[offset]! ^= 0xff
		const pem = `-----BEGIN OPENSSH PRIVATE KEY-----\n${corrupted.toString("base64")}\n-----END OPENSSH PRIVATE KEY-----\n`

		await expect(parsePrivateKey(pem)).rejects.toThrow("private key check values did not match")
	})

	it("should reject text that is not a key", async () => {
		await expect(parsePrivateKey("not a key")).rejects.toThrow(KeyParseError)
	})
})

// signs a KRL with a CA key and verifies the signature with ssh-keygen
const signsFor = async (key: PrivateKey, publicKey: string): Promise<boolean> => {
	const krl = new KRLBuilder(key).addSerials([1n])
	const namespace = "krl@com.github.serverless-ssh-ca.andrewheberle"

	return verifySignature(publicKey, namespace, new Uint8Array(krl.generate()), await krl.signature())
}

// encodes a raw Ed25519 public key in OpenSSH format
const ed25519PublicKey = (x: string): string => {
	const length = (n: number) => [n >>> 24, (n >>> 16) & 0xff, (n >>> 8) & 0xff, n & 0xff]
	const type = new TextEncoder().encode("ssh-ed25519")
	const key = Buffer.from(x, "base64url")

	return `ssh-ed25519 ${Buffer.from([...length(type.length), ...type, ...length(key.length), ...key]).toString("base64")}`
}

describe("parsePrivateKey with a PKCS#8 key", () => {
	// ssh-keygen writes ECDSA keys in PKCS#8 format with -m PKCS8, so the same
	// key is parsed in both formats
	it.each(keyTypes.filter(([name]) => name.startsWith("ECDSA")))("should parse an %s key the same as in OpenSSH format", async (name, type) => {
		const file = createKey(`pkcs8-${name.replace(/\s/g, "-")}`, type)
		const pkcs8 = `${file}-pkcs8`
		copyFileSync(file, pkcs8)
		sshKeygen("-q", "-p", "-N", "", "-m", "PKCS8", "-f", pkcs8)
		const text = readFileSync(pkcs8, "utf8")
		expect(text).toMatch(/^-----BEGIN PRIVATE KEY-----\n/)

		const key = await parsePrivateKey(text)
		const expected = await parsePrivateKey(readFileSync(file, "utf8"))
		const publicKey = readFileSync(`${file}.pub`, "utf8")

		expect(key).toEqual({ ...expected, publicKey: expected.publicKey.withComment(undefined) })
		expect(key.publicKey.equals(PublicKey.parse(publicKey))).toBe(true)
		expect(key.publicKey.comment).toBeUndefined()
		expect(await signsFor(key, publicKey)).toBe(true)
	})

	// ssh-keygen neither reads nor writes Ed25519 keys in PKCS#8 format, so
	// the key is created by Node.js (OpenSSL), as openssl genpkey does
	it("should parse an Ed25519 key", async () => {
		const { privateKey, publicKey } = generateKeyPairSync("ed25519")
		const jwk = publicKey.export({ format: "jwk" })
		if (jwk.x === undefined) {
			throw new Error("Ed25519 public key was missing x")
		}
		const expected = ed25519PublicKey(jwk.x)

		const key = await parsePrivateKey(privateKey.export({ type: "pkcs8", format: "pem" }).toString())

		expect(key.type).toBe("ed25519")
		expect(key.publicKey.toString()).toBe(expected)
		expect(key.jwk).toEqual({ kty: "OKP", crv: "Ed25519", d: privateKey.export({ format: "jwk" }).d, x: jwk.x })
		expect(await signsFor(key, expected)).toBe(true)
	})

	// keys exactly as they are found in a PEM file
	it.each([
		[
			"an Ed25519 key from openssl genpkey",
			`-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIC46HkVY/bKGJu5jNA1nYgR9RYc4GmyRi14c5SJRelvt
-----END PRIVATE KEY-----
`,
			"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIK1JQHS0+pLo8MMOcLJ8L7gDoKTy7y3y2djZkEUOyxza",
		],
		[
			"an ECDSA nistp256 key from ssh-keygen -m PKCS8",
			`-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgc/0ZTD32fon9JZnu
Tm5SAmEroColGIRXbKyBugIe0RihRANCAATozLGNk+TxyvtJVjo62YRjqzYgM++P
sluwnFhR9lPnDTo7NZmqsE1Go8VWfmkfsc98kTf/pSTxudY172PG0tsp
-----END PRIVATE KEY-----
`,
			"ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBOjMsY2T5PHK+0lWOjrZhGOrNiAz74+yW7CcWFH2U+cNOjs1maqwTUajxVZ+aR+xz3yRN/+lJPG51jXvY8bS2yk=",
		],
	])("should parse %s", async (_, pem, publicKey) => {
		for (const text of [pem, pem.replace(/\n/g, "\r\n"), `\n  ${pem}\n`]) {
			const key = await parsePrivateKey(text)

			expect(key.publicKey.toString()).toBe(publicKey)
			expect(await signsFor(key, publicKey)).toBe(true)
		}
	})

	it("should reject an RSA key", async () => {
		const file = createKey("pkcs8-rsa", ["-t", "rsa", "-b", "2048"], ["-m", "PKCS8"])
		const text = readFileSync(file, "utf8")
		expect(text).toMatch(/^-----BEGIN PRIVATE KEY-----\n/)

		await expect(parsePrivateKey(text)).rejects.toThrow(UnsupportedKeyError)
		await expect(parsePrivateKey(text)).rejects.toThrow("CA key type rsa is not supported, the CA key must be Ed25519 or ECDSA")
	})

	it("should reject an encrypted key", async () => {
		const file = createKey("pkcs8-encrypted", ["-t", "ecdsa", "-b", "256"])
		sshKeygen("-q", "-p", "-N", "a passphrase", "-m", "PKCS8", "-f", file)
		const text = readFileSync(file, "utf8")
		expect(text).toMatch(/^-----BEGIN ENCRYPTED PRIVATE KEY-----\n/)

		await expect(parsePrivateKey(text)).rejects.toThrow(KeyParseError)
		await expect(parsePrivateKey(text)).rejects.toThrow("encrypted private keys are not supported")
	})

	it("should reject a key that cannot be imported", async () => {
		const pem = "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VxBCIEIC46HkVY/bKGJu5jNA1nYgR9RYc4GmyRi14c5SJRelvt\n-----END PRIVATE KEY-----\n"

		await expect(parsePrivateKey(pem)).rejects.toThrow(KeyParseError)
		await expect(parsePrivateKey(pem)).rejects.toThrow("PKCS#8 private key could not be imported as an Ed25519 or ECDSA (nistp256, nistp384 or nistp521) key")
	})

	it("should reject a key that is not base64", async () => {
		await expect(parsePrivateKey("-----BEGIN PRIVATE KEY-----\n!!!\n-----END PRIVATE KEY-----\n")).rejects.toThrow("private key could not be decoded")
	})
})

// returns the offset of the length of the private section of an OpenSSH private key
const findPrivateSection = (body: Buffer): number => {
	let offset = 15 // "openssh-key-v1\0"
	const skipString = () => {
		offset += 4 + body.readUInt32BE(offset)
	}
	skipString() // cipher name
	skipString() // kdf name
	skipString() // kdf options
	const count = body.readUInt32BE(offset)
	offset += 4
	for (let i = 0; i < count; i++) {
		skipString() // public key
	}

	return offset
}

describe("PublicKey", () => {
	it.each([...keyTypes, ["RSA", ["-t", "rsa", "-b", "2048"]] as [string, string[]]])("should parse an %s key with the fingerprint shown by ssh-keygen", (name, type) => {
		const file = createKey(`public-${name.replace(/\s/g, "-")}`, type)
		const text = readFileSync(`${file}.pub`, "utf8")
		const key = PublicKey.parse(text)

		// ssh-keygen -l prints "<bits> <fingerprint> <comment> (<type>)"
		expect(sshKeygen("-l", "-f", `${file}.pub`).split(" ")[1]).toBe(key.fingerprint())
		expect(key.toString()).toBe(text.trim())
		expect(key.comment).toBe(`public-${name.replace(/\s/g, "-")}@example.com`)
	})

	it("should compare keys without their comments", () => {
		const file = createKey("compare", ["-t", "ed25519"])
		const key = PublicKey.parse(readFileSync(`${file}.pub`, "utf8"))

		expect(key.equals(key.withComment("another comment"))).toBe(true)
		expect(key.withComment(undefined).toString()).toBe(key.toString().split(" ").slice(0, 2).join(" "))
	})

	it.each([
		["an empty string", ""],
		["a key without data", "ssh-ed25519"],
		["invalid base64", "ssh-ed25519 !!!"],
		["a key whose type does not match its encoding", "ssh-rsa AAAAC3NzaC1lZDI1NTE5AAAAIJdUPCIzcbitJtPIAKcE0S0RKkUDSbl3XS8zDV8b/RcG"],
		["an unsupported key type", "ssh-dss AAAAB3NzaC1kc3MAAAAA"],
		["a truncated key", "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA"],
	])("should reject %s", (_, text) => {
		expect(() => PublicKey.parse(text)).toThrow(KeyParseError)
	})
})

describe("SshCertificate", () => {
	describe.each(keyTypes)("signed by ssh-keygen with an %s CA key", (name, type) => {
		const certify = (kind: "user" | "host") => {
			const prefix = `cert-${kind}-${name.replace(/\s/g, "-")}`
			const ca = createKey(`${prefix}-ca`, type)
			const subject = createKey(`${prefix}-subject`, ["-t", "ed25519"])
			sshKeygen("-q", "-s", ca, "-I", "key-id", "-n", "alice,bob", "-z", "1234", "-V", "20260101000000:20270101000000", ...(kind === "host" ? ["-h"] : ["-O", "clear", "-O", "permit-pty"]), `${subject}.pub`)

			return {
				ca: PublicKey.parse(readFileSync(`${ca}.pub`, "utf8")),
				subject: PublicKey.parse(readFileSync(`${subject}.pub`, "utf8")),
				certificate: SshCertificate.parse(readFileSync(`${subject}-cert.pub`, "utf8")),
			}
		}

		it("should parse and verify a user certificate", async () => {
			const { ca, subject, certificate } = certify("user")

			expect(certificate.kind).toBe("user")
			expect(certificate.type).toBe("ssh-ed25519-cert-v01@openssh.com")
			expect(certificate.publicKey.equals(subject)).toBe(true)
			expect(certificate.serial).toBe(1234n)
			expect(certificate.keyId).toBe("key-id")
			expect(certificate.principals).toEqual(["alice", "bob"])
			expect(certificate.validAfter).toEqual(new Date(2026, 0, 1))
			expect(certificate.validBefore).toEqual(new Date(2027, 0, 1))
			expect(certificate.extensions).toEqual(["permit-pty"])
			expect(await certificate.isSignedBy(ca)).toBe(true)
		})

		it("should parse and verify a host certificate", async () => {
			const { ca, certificate } = certify("host")

			expect(certificate.kind).toBe("host")
			expect(certificate.principals).toEqual(["alice", "bob"])
			expect(certificate.extensions).toEqual([])
			expect(await certificate.isSignedBy(ca)).toBe(true)
		})

		it("should not verify with another CA key", async () => {
			const { certificate } = certify("user")
			const other = PublicKey.parse(readFileSync(`${createKey(`other-${name.replace(/\s/g, "-")}`, type)}.pub`, "utf8"))

			expect(await certificate.isSignedBy(other)).toBe(false)
		})

		it("should not verify with a modified field", async () => {
			const { ca, certificate } = certify("user")
			const bytes = new Uint8Array(certificate.bytes)
			// the serial follows the nonce and the key, so change the last
			// byte of the principals instead, which is easier to find
			const principals = new TextEncoder().encode("bob")
			const offset = Buffer.from(bytes).indexOf(Buffer.from(principals))
			bytes[offset]! ^= 0x01

			expect(await new SshCertificate(bytes).isSignedBy(ca)).toBe(false)
		})
	})

	it.each([
		["an empty string", ""],
		["invalid base64", "ssh-ed25519-cert-v01@openssh.com !!!"],
		["a public key", "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJdUPCIzcbitJtPIAKcE0S0RKkUDSbl3XS8zDV8b/RcG"],
		["a truncated certificate", "ssh-ed25519-cert-v01@openssh.com AAAAIHNzaC1lZDI1NTE5LWNlcnQtdjAxQG9wZW5zc2guY29t"],
	])("should not parse %s", (_, text) => {
		expect(() => SshCertificate.parse(text)).toThrow(CertificateParseError)
	})
})
