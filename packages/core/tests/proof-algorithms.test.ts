import { afterEach, describe, it, expect, vi } from "vitest"
import { createHash, createSign, generateKeyPairSync, sign } from "node:crypto"
import { DatabaseSync } from "node:sqlite"
import { createSshCa } from "../src/index.js"
import { fromNodeSqlite, secretFromString } from "../src/node/index.js"
import { makeEnv } from "./env.js"
import { key as ed25519Key } from "./keys/ed25519.js"

// Proofs of possession built by hand, so the signature algorithm, hash and
// key can be ones that ssh-keygen would never produce. A proof that is not
// valid is the requester's fault, so it must get a 400, never a 500 (#600)

const namespace = "request-proof-of-possession@com.github.serverless-ssh-ca.andrewheberle"
const path = "/api/v4/user/certificates/1234"

const string = (value: Buffer | string): Buffer => {
	const bytes = Buffer.isBuffer(value) ? value : Buffer.from(value)
	const length = Buffer.alloc(4)
	length.writeUInt32BE(bytes.length)
	return Buffer.concat([length, bytes])
}

const mpint = (value: Buffer): Buffer => {
	let bytes = value
	while (bytes.length > 1 && bytes[0] === 0) {
		bytes = bytes.subarray(1)
	}
	return string((bytes[0] ?? 0) & 0x80 ? Buffer.concat([Buffer.from([0]), bytes]) : bytes)
}

const fingerprint = (blob: Buffer): string => `SHA256:${createHash("sha256").update(blob).digest("base64").replace(/=+$/, "")}`

// a proof for DELETE `path`, signed with `signWith` as `signatureAlgorithm`
const proof = (keyBlob: Buffer, signatureAlgorithm: string, signWith: (data: Buffer) => Buffer, hash: "sha256" | "sha512" | "md5" = "sha512"): string => {
	const timestamp = Date.now()
	const message = `${timestamp}.${fingerprint(keyBlob)}.DELETE ${path}`
	const digest = createHash(hash === "md5" ? "sha512" : hash).update(message).digest()
	const signed = Buffer.concat([Buffer.from("SSHSIG"), string(namespace), string(""), string(hash), string(digest)])
	const signature = string(Buffer.concat([string(signatureAlgorithm), string(signWith(signed))]))
	const version = Buffer.alloc(4)
	version.writeUInt32BE(1)
	const blob = Buffer.concat([Buffer.from("SSHSIG"), version, string(keyBlob), string(namespace), string(""), string(hash), signature])
	const armored = `-----BEGIN SSH SIGNATURE-----\n${blob.toString("base64").match(/.{1,70}/g)?.join("\n") ?? ""}\n-----END SSH SIGNATURE-----\n`

	return `${timestamp}.${fingerprint(keyBlob)}.${Buffer.from(armored).toString("base64")}`
}

const rsa = generateKeyPairSync("rsa", { modulusLength: 2048 })
const rsaJwk = rsa.publicKey.export({ format: "jwk" })
const rsaBlob = Buffer.concat([string("ssh-rsa"), mpint(Buffer.from(rsaJwk.e ?? "", "base64url")), mpint(Buffer.from(rsaJwk.n ?? "", "base64url"))])
const rsaSign = (hash: string) => (data: Buffer): Buffer => createSign(hash).update(data).sign(rsa.privateKey)

const ed = generateKeyPairSync("ed25519")
const edRaw = Buffer.from(ed.publicKey.export({ format: "jwk" }).x ?? "", "base64url")
const edBlob = Buffer.concat([string("ssh-ed25519"), string(edRaw)])
const edShortBlob = Buffer.concat([string("ssh-ed25519"), string(edRaw.subarray(0, 31))])
const edSign = (data: Buffer): Buffer => sign(null, data, ed.privateKey)

const revoke = async (proofOfPossession: string): Promise<Response> => await createSshCa(makeEnv({
	DB: fromNodeSqlite(new DatabaseSync(":memory:")),
	PRIVATE_KEY: secretFromString(ed25519Key.ca().privateKey),
	LOG_LEVEL: "warning",
})).fetch(new Request(`http://example.com${path}`, { method: "DELETE", headers: { "Proof-Of-Possession": proofOfPossession } }))

describe("proofs of possession by signature algorithm", () => {
	afterEach(() => {
		vi.restoreAllMocks()
	})

	it.each([
		["an RSA key with rsa-sha2-512", () => proof(rsaBlob, "rsa-sha2-512", rsaSign("RSA-SHA512"))],
		["an RSA key with rsa-sha2-256", () => proof(rsaBlob, "rsa-sha2-256", rsaSign("RSA-SHA256"))],
		["an RSA key with rsa-sha2-256 over a sha256 hash", () => proof(rsaBlob, "rsa-sha2-256", rsaSign("RSA-SHA256"), "sha256")],
		["an Ed25519 key", () => proof(edBlob, "ssh-ed25519", edSign)],
	])("should accept %s", async (_name, make) => {
		vi.spyOn(console, "log").mockImplementation(() => undefined)

		// the proof is accepted, so the revocation fails only as the certificate is unknown
		const response = await revoke(make())
		expect(response.status).toBe(404)
		expect(await response.json()).toMatchObject({ errors: [{ message: "certificate not found" }] })
	})

	it.each([
		["an RSA key with ssh-rsa (SHA-1)", () => proof(rsaBlob, "ssh-rsa", rsaSign("RSA-SHA1"))],
		["an Ed25519 key with rsa-sha2-512", () => proof(edBlob, "rsa-sha2-512", edSign)],
		["an Ed25519 key with an unknown algorithm", () => proof(edBlob, "nope", edSign)],
		["an RSA key with ssh-ed25519", () => proof(rsaBlob, "ssh-ed25519", rsaSign("RSA-SHA512"))],
		["a 31 byte Ed25519 key", () => proof(edShortBlob, "ssh-ed25519", edSign)],
		["an unsupported hash algorithm", () => proof(edBlob, "ssh-ed25519", edSign, "md5")],
	])("should refuse %s with a 400 and log it as a warning", async (_name, make) => {
		const log = vi.spyOn(console, "log").mockImplementation(() => undefined)

		const response = await revoke(make())

		expect(response.status).toBe(400)
		expect(await response.json()).toMatchObject({ errors: [{ path: ["headers", "Proof-Of-Possession"] }] })
		expect(log).not.toHaveBeenCalledWith(expect.objectContaining({ level: "error" }))
		expect(log).toHaveBeenCalledWith(expect.objectContaining({ level: "warning" }))
	})
})
