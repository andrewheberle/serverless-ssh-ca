import { afterEach, beforeEach, describe, expect, it, vi } from "vitest"
import { DatabaseSync } from "node:sqlite"
import { z } from "zod"
import worker, { cloudflareClientIp, createSshCa, type SshCa, type SshCaBindings, type SshCaOptions } from "../src/index.js"
import { clientAddressOf } from "../src/client-address.js"
import { revokeCertificate } from "../src/db/index.js"
import { applyMigrations } from "../src/db/migrate.js"
import { migrations } from "../src/db/migrations/index.js"
import { CertificateType } from "../src/db/types.js"
import { fromNodeSqlite, secretFromString } from "../src/node/index.js"
import { SshCertificate } from "../src/ssh/certificate.js"
import { makeEnv } from "./env.js"
import { generateRequestProof } from "./helpers/proof.js"
import { getAccessToken, getIdentityToken } from "./helpers/token.js"
import { key as ecdsaKey } from "./keys/ecdsa.js"
import { key as ed25519Key } from "./keys/ed25519.js"
import type { TestKey } from "./keys/types.js"

const email = "user@example.com"
const claims = { sub: "user123", email }

// the header the client address is read from in these tests
const AddressHeader = "X-Test-Client-Address"
const fromHeader: SshCaOptions["clientAddress"] = (req) => req.headers.get(AddressHeader) ?? undefined

const CertificateResponse = z.object({ certificate: z.string() })
const AddressRow = z.object({ request_address: z.string().nullable(), revocation_address: z.string().nullable() })

const base64 = (value: string): string => Buffer.from(value).toString("base64")

describe("clientAddressOf", () => {
	const request = (address?: string): Request => new Request("http://example.com", {
		headers: address === undefined ? {} : { [AddressHeader]: address },
	})

	it.each([
		["an IPv4 address", "192.0.2.10"],
		["an IPv6 address", "2001:db8::1"],
		["an IPv4-mapped IPv6 address", "::ffff:192.0.2.10"],
	])("should accept %s", (_name, address) => {
		expect(clientAddressOf(fromHeader, request(address))).toEqual({ kind: "known", address })
	})

	it("should know no address without a source", () => {
		expect(clientAddressOf(undefined, request("192.0.2.10"))).toEqual({ kind: "none" })
	})

	it.each([
		["no value", undefined],
		["an empty value", ""],
	])("should know no address when the source gives %s", (_name, address) => {
		expect(clientAddressOf(fromHeader, request(address))).toEqual({ kind: "none" })
	})

	it.each([
		["a host name", "client.example.com"],
		["a list of addresses", "192.0.2.10, 198.51.100.1"],
		["an address with a port", "192.0.2.10:443"],
	])("should refuse %s", (_name, value) => {
		expect(clientAddressOf(fromHeader, request(value))).toEqual({ kind: "invalid", value })
	})
})

describe("recording client addresses", () => {
	let sqlite: DatabaseSync
	let env: SshCaBindings
	let ca: SshCa

	const addresses = (serial: bigint): z.infer<typeof AddressRow> => AddressRow.parse(
		sqlite.prepare("SELECT request_address, revocation_address FROM certificates WHERE serial = ?").get(`${serial}`),
	)

	const post = async (path: string, body: unknown, headers: Record<string, string>, address?: string): Promise<Response> => await ca.fetch(new Request(`http://example.com${path}`, {
		method: "POST",
		headers: { "Content-Type": "application/json", ...headers, ...(address === undefined ? {} : { [AddressHeader]: address }) },
		body: JSON.stringify(body),
	}))

	const certificateOf = async (response: Response): Promise<{ text: string, certificate: SshCertificate }> => {
		expect(response.status).toBe(200)
		const text = Buffer.from(CertificateResponse.parse(await response.json()).certificate, "base64").toString()
		return { text, certificate: SshCertificate.parse(text) }
	}

	const issueUserV4 = async (key: TestKey, address?: string): Promise<Response> => await post("/api/v4/user/certificates", {
		public_key: base64(key.publicKey),
		identity: await getIdentityToken(claims),
	}, {
		"Authorization": await getAccessToken(claims),
		"Proof-Of-Possession": generateRequestProof(key, "POST", "/api/v4/user/certificates"),
	}, address)

	const issueHostV4 = async (key: TestKey, address?: string): Promise<Response> => await post("/api/v4/host/certificates", {
		public_key: base64(key.publicKey),
		identity: await getIdentityToken(claims),
		principals: ["address.example.com"],
	}, {
		"Authorization": await getAccessToken(claims),
		"Proof-Of-Possession": generateRequestProof(key, "POST", "/api/v4/host/certificates"),
	}, address)

	const renewV4 = async (issued: { text: string, certificate: SshCertificate }, key: TestKey, address?: string): Promise<Response> => {
		const path = `/api/v4/host/certificates/${issued.certificate.serial}/renew`
		return await post(path, { certificate: base64(issued.text) }, { "Proof-Of-Possession": generateRequestProof(key, "POST", path) }, address)
	}

	const revokeV4 = async (serial: bigint, key: TestKey, address?: string): Promise<Response> => {
		const path = `/api/v4/user/certificates/${serial}`
		return await ca.fetch(new Request(`http://example.com${path}`, {
			method: "DELETE",
			headers: { "Proof-Of-Possession": generateRequestProof(key, "DELETE", path), ...(address === undefined ? {} : { [AddressHeader]: address }) },
		}))
	}

	const create = (options: SshCaOptions, bindings: Partial<SshCaBindings> = {}): SshCa => createSshCa(makeEnv({
		DB: fromNodeSqlite(sqlite),
		PRIVATE_KEY: secretFromString(ed25519Key.ca().privateKey),
		SSH_HOST_CERTIFICATE_ALLOWED_EMAILS: email,
		...bindings,
	}), options)

	beforeEach(() => {
		sqlite = new DatabaseSync(":memory:")
		env = makeEnv({
			DB: fromNodeSqlite(sqlite),
			PRIVATE_KEY: secretFromString(ed25519Key.ca().privateKey),
			SSH_HOST_CERTIFICATE_ALLOWED_EMAILS: email,
		})
		ca = create({ clientAddress: fromHeader })
	})

	afterEach(() => {
		vi.restoreAllMocks()
		sqlite.close()
	})

	it.each([
		["a user certificate (v4)", issueUserV4, ecdsaKey.user],
		["a host certificate (v4)", issueHostV4, ecdsaKey.host],
	])("should record the request address when issuing %s", async (_name, issue, key) => {
		const { certificate } = await certificateOf(await issue(key(), "192.0.2.10"))

		expect(addresses(certificate.serial)).toEqual({ request_address: "192.0.2.10", revocation_address: null })
	})

	it("should record the address of a renewal as the request address of the renewal and the revocation address of what it renewed", async () => {
		const key = ecdsaKey.host()
		const issued = await certificateOf(await issueHostV4(key, "192.0.2.10"))

		const renewed = await certificateOf(await renewV4(issued, key, "2001:db8::1"))

		expect(addresses(issued.certificate.serial)).toEqual({ request_address: "192.0.2.10", revocation_address: "2001:db8::1" })
		expect(addresses(renewed.certificate.serial)).toEqual({ request_address: "2001:db8::1", revocation_address: null })
	})

	it("should record the revocation address of a revocation by the key holder", async () => {
		const key = ecdsaKey.user()
		const { certificate } = await certificateOf(await issueUserV4(key, "192.0.2.10"))

		expect((await revokeV4(certificate.serial, key, "198.51.100.7")).status).toBe(200)

		expect(addresses(certificate.serial)).toEqual({ request_address: "192.0.2.10", revocation_address: "198.51.100.7" })
	})

	it("should record no address for a revocation by an admin", async () => {
		const { certificate } = await certificateOf(await issueUserV4(ecdsaKey.user(), "192.0.2.10"))

		const result = await revokeCertificate(env, { serial: certificate.serial, certificateType: CertificateType.User, revoker: { kind: "admin", email: "admin@example.com", reason: "lost" } })

		expect(result.kind).toBe("revoked")
		expect(addresses(certificate.serial)).toEqual({ request_address: "192.0.2.10", revocation_address: null })
	})

	it("should record no address without a source, whatever headers the client sends", async () => {
		ca = create({})
		const key = ecdsaKey.user()
		const response = await ca.fetch(new Request("http://example.com/api/v4/user/certificates", {
			method: "POST",
			headers: {
				"Content-Type": "application/json",
				"Authorization": await getAccessToken(claims),
				"Proof-Of-Possession": generateRequestProof(key, "POST", "/api/v4/user/certificates"),
				"CF-Connecting-IP": "192.0.2.10",
				[AddressHeader]: "192.0.2.10",
			},
			body: JSON.stringify({ public_key: base64(key.publicKey), identity: await getIdentityToken(claims) }),
		}))

		const { certificate } = await certificateOf(response)

		expect(addresses(certificate.serial)).toEqual({ request_address: null, revocation_address: null })
	})

	it("should record no address that is not an IP address, still issue the certificate, and warn once", async () => {
		const log = vi.spyOn(console, "log").mockImplementation(() => undefined)
		ca = create({ clientAddress: fromHeader }, { LOG_LEVEL: "info" })

		const first = await certificateOf(await issueUserV4(ecdsaKey.user(), "client.example.com"))
		const second = await certificateOf(await issueUserV4(ecdsaKey.user(), "not an address"))

		expect(addresses(first.certificate.serial)).toEqual({ request_address: null, revocation_address: null })
		expect(addresses(second.certificate.serial)).toEqual({ request_address: null, revocation_address: null })
		const warnings = log.mock.calls.filter(([entry]) => z.object({ message: z.literal("client addresses that are not IP addresses are not recorded") }).safeParse(entry).success)
		expect(warnings).toEqual([[expect.objectContaining({ level: "warning", value: "client.example.com" })]])
	})

	it("should log the client address of an issued certificate and a revocation", async () => {
		const log = vi.spyOn(console, "log").mockImplementation(() => undefined)
		ca = create({ clientAddress: fromHeader }, { LOG_LEVEL: "info" })
		const key = ecdsaKey.user()

		const { certificate } = await certificateOf(await issueUserV4(key, "192.0.2.10"))
		expect((await revokeV4(certificate.serial, key, "198.51.100.7")).status).toBe(200)

		expect(log).toHaveBeenCalledWith(expect.objectContaining({ message: "completed issuing certificate", client_address: "192.0.2.10" }))
		expect(log).toHaveBeenCalledWith(expect.objectContaining({ message: "certificate revoked", serial: `${certificate.serial}`, client_address: "198.51.100.7" }))
	})

	it("should not log a client address that is not known", async () => {
		const log = vi.spyOn(console, "log").mockImplementation(() => undefined)
		ca = create({}, { LOG_LEVEL: "info" })

		await certificateOf(await issueUserV4(ecdsaKey.user()))

		expect(log).toHaveBeenCalledWith(expect.objectContaining({ message: "completed issuing certificate" }))
		expect(log).not.toHaveBeenCalledWith(expect.objectContaining({ client_address: expect.anything() }))
	})

	it("should record the address from CF-Connecting-IP with the Workers default export", async () => {
		const ctx = { waitUntil: () => undefined, passThroughOnException: () => undefined, props: {} }
		const key = ecdsaKey.user()
		const response = await worker.fetch(new Request("http://example.com/api/v4/user/certificates", {
			method: "POST",
			headers: {
				"Content-Type": "application/json",
				"Authorization": await getAccessToken(claims),
				"Proof-Of-Possession": generateRequestProof(key, "POST", "/api/v4/user/certificates"),
				"CF-Connecting-IP": "203.0.113.5",
			},
			body: JSON.stringify({ public_key: base64(key.publicKey), identity: await getIdentityToken(claims) }),
		}), env, ctx)

		const { certificate } = await certificateOf(response)

		expect(addresses(certificate.serial)).toEqual({ request_address: "203.0.113.5", revocation_address: null })
	})

	it("should record the address cloudflareClientIp gives with createSshCa", async () => {
		ca = create({ clientAddress: cloudflareClientIp })
		const key = ecdsaKey.user()
		const response = await ca.fetch(new Request("http://example.com/api/v4/user/certificates", {
			method: "POST",
			headers: {
				"Content-Type": "application/json",
				"Authorization": await getAccessToken(claims),
				"Proof-Of-Possession": generateRequestProof(key, "POST", "/api/v4/user/certificates"),
				"CF-Connecting-IP": "203.0.113.5",
			},
			body: JSON.stringify({ public_key: base64(key.publicKey), identity: await getIdentityToken(claims) }),
		}))

		const { certificate } = await certificateOf(response)

		expect(addresses(certificate.serial).request_address).toBe("203.0.113.5")
	})
})

describe("migration 0006_client_address", () => {
	it("should keep existing certificates, leaving their client addresses unknown", async () => {
		const raw = new DatabaseSync(":memory:")
		await applyMigrations(fromNodeSqlite(raw), migrations.filter((m) => m.name !== "0006_client_address"))
		raw.exec(`INSERT INTO certificates (serial, key_id, principals, extensions, valid_after, valid_before, revoked_at, certificate_type, public_key, requested_by, revoked_by)
			VALUES ('1234', 'user@example.com', 'UID=user', 'permit-pty', '2026-01-01T00:00:00.000Z', '2026-01-02T00:00:00.000Z', '2026-01-01T12:00:00.000Z', 0, 'ssh-ed25519 AAAA', 'user@example.com', 'key-holder')`)

		expect((await applyMigrations(fromNodeSqlite(raw), migrations)).map((m) => m.name)).toEqual(["0006_client_address"])

		expect(raw.prepare("SELECT serial, requested_by, revoked_by, request_address, revocation_address FROM certificates").all()).toEqual([{
			serial: "1234",
			requested_by: "user@example.com",
			revoked_by: "key-holder",
			request_address: null,
			revocation_address: null,
		}])
	})
})
