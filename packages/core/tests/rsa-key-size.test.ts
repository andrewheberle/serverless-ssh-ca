import { describe, it, expect, beforeAll } from "vitest"
import { DatabaseSync } from "node:sqlite"
import { createSshCa, type SshCa } from "../src/index.js"
import { fromNodeSqlite, secretFromString } from "../src/node/index.js"
import { PublicKey, rsaKeyBits } from "../src/ssh/keys.js"
import { subjectKeyIssue } from "../src/utils.js"
import { makeEnv } from "./env.js"
import { getAccessToken, getIdentityToken } from "./helpers/token.js"
import { generateProof, generateRequestProof } from "./helpers/proof.js"
import { generateKey } from "./helpers/ssh-keygen.js"
import type { TestKey } from "./keys/types.js"
import { key as ed25519Key } from "./keys/ed25519.js"
import { key as ecdsaKey } from "./keys/ecdsa.js"

const email = "user@example.com"
const claims = { sub: "user123", email }

const encode = (key: TestKey): string => Buffer.from(key.publicKey).toString("base64")

describe("rsaKeyBits", () => {
	it.each([1024, 2048, 3072])("should return %i for an RSA key of that size", (bits) => {
		expect(rsaKeyBits(PublicKey.parse(generateKey("rsa", bits).publicKey))).toBe(bits)
	})

	it("should return undefined for a key that is not RSA", () => {
		expect(rsaKeyBits(PublicKey.parse(ed25519Key.user().publicKey))).toBeUndefined()
		expect(rsaKeyBits(PublicKey.parse(ecdsaKey.user().publicKey))).toBeUndefined()
	})
})

describe("subjectKeyIssue", () => {
	it("should refuse an RSA key smaller than 2048 bits", () => {
		expect(subjectKeyIssue(PublicKey.parse(generateKey("rsa", 1024).publicKey))).toBe("RSA keys must be at least 2048 bits, not 1024")
	})

	it.each([2048, 3072])("should allow an RSA key of %i bits", (bits) => {
		expect(subjectKeyIssue(PublicKey.parse(generateKey("rsa", bits).publicKey))).toBeUndefined()
	})

	it("should allow keys that are not RSA", () => {
		expect(subjectKeyIssue(PublicKey.parse(ed25519Key.user().publicKey))).toBeUndefined()
	})
})

describe("certificate requests with small RSA keys", () => {
	let ca: SshCa
	let small: TestKey
	let large: TestKey

	beforeAll(() => {
		ca = createSshCa(makeEnv({
			DB: fromNodeSqlite(new DatabaseSync(":memory:")),
			PRIVATE_KEY: secretFromString(ed25519Key.ca().privateKey),
			SSH_HOST_CERTIFICATE_ALLOWED_EMAILS: email,
		}))
		small = generateKey("rsa", 1024)
		large = generateKey("rsa", 2048)
	})

	const post = async (path: string, body: Record<string, unknown>, headers: Record<string, string> = {}): Promise<Response> => {
		return await ca.fetch(new Request(`http://example.com${path}`, {
			method: "POST",
			headers: { "Content-Type": "application/json", "Authorization": await getAccessToken(claims), ...headers },
			body: JSON.stringify(body),
		}))
	}

	const requests: [string, (key: TestKey) => Promise<Response>][] = [
		["POST /api/v3/user/certificate", async (key) => await post("/api/v3/user/certificate", {
			public_key: encode(key), proof: generateProof(key), identity: await getIdentityToken(claims),
		})],
		["POST /api/v3/host/certificate", async (key) => await post("/api/v3/host/certificate", {
			public_key: encode(key), proof: generateProof(key), identity: await getIdentityToken(claims), principals: ["test_host"],
		})],
		["POST /api/v4/user/certificates", async (key) => await post("/api/v4/user/certificates", {
			public_key: encode(key), identity: await getIdentityToken(claims),
		}, { "Proof-Of-Possession": generateRequestProof(key, "POST", "/api/v4/user/certificates") })],
		["POST /api/v4/host/certificates", async (key) => await post("/api/v4/host/certificates", {
			public_key: encode(key), identity: await getIdentityToken(claims), principals: ["test_host"],
		}, { "Proof-Of-Possession": generateRequestProof(key, "POST", "/api/v4/host/certificates") })],
	]

	it.each(requests)("%s should refuse a 1024 bit RSA key", async (_name, request) => {
		expect((await request(small)).status).toBe(400)
	})

	it.each(requests)("%s should accept a 2048 bit RSA key", async (_name, request) => {
		expect((await request(large)).status).toBe(200)
	})

	it("should still accept a revocation proven with a small RSA key", async () => {
		// revocation must keep working for certificates issued before the minimum,
		// so an unknown serial is reported as not found rather than refused
		const response = await ca.fetch(new Request("http://example.com/api/v4/user/certificates/12345", {
			method: "DELETE",
			headers: { "Proof-Of-Possession": generateRequestProof(small, "DELETE", "/api/v4/user/certificates/12345") },
		}))
		expect(response.status).toBe(404)
	})
})
