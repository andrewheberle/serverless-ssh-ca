import { describe, it, expect } from "vitest"
import { DatabaseSync } from "node:sqlite"
import { createSshCa, type SshCa } from "../src/index.js"
import { fromNodeSqlite, secretFromString } from "../src/node/index.js"
import type { SshCaBindings } from "../src/types.js"
import { makeEnv } from "./env.js"
import { getAccessToken, getIdentityToken, type TokenClaims } from "./helpers/token.js"
import { generateRequestProof } from "./helpers/proof.js"
import { key as ed25519Key } from "./keys/ed25519.js"
import { key as ecdsaKey } from "./keys/ecdsa.js"
import openapi from "../openapi.json" with { type: "json" }

// Every error response must match the response schema openapi.json declares
// for its operation and status, as clients generate their code from it

type Schema = {
	$ref?: string
	type?: string
	enum?: unknown[]
	properties?: Record<string, Schema>
	required?: string[]
	items?: Schema
}

const resolve = (schema: Schema): Schema => {
	if (schema.$ref === undefined) {
		return schema
	}
	const name = schema.$ref.replace("#/components/schemas/", "")
	// the reference comes from openapi.json itself, so it names a component
	const components = openapi.components.schemas as Record<string, Schema>
	const resolved = components[name]
	if (resolved === undefined) {
		throw new Error(`unknown component ${name}`)
	}
	return resolved
}

// the ways a value does not match a schema, using only the keywords
// openapi.json uses for responses
const mismatches = (value: unknown, schema: Schema, at = "$"): string[] => {
	const s = resolve(schema)
	if (s.enum !== undefined && !s.enum.includes(value)) {
		return [`${at} is not one of ${JSON.stringify(s.enum)}`]
	}
	switch (s.type) {
		case "object": {
			if (typeof value !== "object" || value === null || Array.isArray(value)) {
				return [`${at} is not an object`]
			}
			const record = value as Record<string, unknown>
			return [
				...(s.required ?? []).filter((key) => !(key in record)).map((key) => `${at}.${key} is missing`),
				...Object.entries(s.properties ?? {}).flatMap(([key, property]) => key in record ? mismatches(record[key], property, `${at}.${key}`) : []),
			]
		}
		case "array":
			return Array.isArray(value)
				? value.flatMap((item, i) => s.items === undefined ? [] : mismatches(item, s.items, `${at}[${i}]`))
				: [`${at} is not an array`]
		case "string":
		case "number":
		case "boolean":
			return typeof value === s.type ? [] : [`${at} is not a ${s.type}`]
		default:
			return []
	}
}

type Operation = { responses: Record<string, { content?: Record<string, { schema: Schema }> }> }

const responseSchema = (path: string, method: "post" | "delete", status: number): Schema => {
	const operation = (openapi.paths as Record<string, Partial<Record<string, Operation>>>)[path]?.[method]
	const schema = operation?.responses[`${status}`]?.content?.["application/json"]?.schema
	if (schema === undefined) {
		throw new Error(`openapi.json documents no ${status} for ${method.toUpperCase()} ${path}`)
	}
	return schema
}

const caKey = ed25519Key.ca()
const userKey = ecdsaKey.user()
const hostKey = ecdsaKey.host()
const claims: TokenClaims = { sub: "user123", email: "user@example.com" }
const base64 = (value: string): string => Buffer.from(value).toString("base64")

const newCa = (overrides: Partial<SshCaBindings> = {}): SshCa => createSshCa(makeEnv({
	DB: fromNodeSqlite(new DatabaseSync(":memory:")),
	PRIVATE_KEY: secretFromString(caKey.privateKey),
	SSH_HOST_CERTIFICATE_ALLOWED_EMAILS: claims.email,
	...overrides,
}))

const issueUser = async (ca: SshCa, body: Record<string, unknown> = {}, identity: Record<string, unknown> = claims): Promise<Response> => await ca.fetch(new Request("http://example.com/api/v4/user/certificates", {
	method: "POST",
	headers: {
		"Content-Type": "application/json",
		"Authorization": await getAccessToken(claims),
		"Proof-Of-Possession": generateRequestProof(userKey, "POST", "/api/v4/user/certificates"),
	},
	body: JSON.stringify({ public_key: base64(userKey.publicKey), identity: await getIdentityToken(identity as TokenClaims), ...body }),
}))

const issueHost = async (ca: SshCa, body: Record<string, unknown> = {}): Promise<Response> => await ca.fetch(new Request("http://example.com/api/v4/host/certificates", {
	method: "POST",
	headers: {
		"Content-Type": "application/json",
		"Authorization": await getAccessToken(claims),
		"Proof-Of-Possession": generateRequestProof(hostKey, "POST", "/api/v4/host/certificates"),
	},
	body: JSON.stringify({ public_key: base64(hostKey.publicKey), identity: await getIdentityToken(claims), principals: ["host.example.com"], ...body }),
}))

type Case = {
	name: string
	path: string
	method: "post" | "delete"
	status: number
	request: () => Promise<Response>
	errorPath?: string[]
}

const cases: Case[] = [
	{
		name: "an extension that is not allowed",
		path: "/api/v4/user/certificates", method: "post", status: 422,
		request: async () => await issueUser(newCa(), { extensions: ["no-such-ext"] }),
		errorPath: ["body", "extensions"],
	},
	{
		name: "a user certificate without principals",
		path: "/api/v4/user/certificates", method: "post", status: 422,
		request: async () => await issueUser(newCa({ SSH_CERTIFICATE_PRINCIPALS: undefined })),
		errorPath: ["body"],
	},
	{
		name: "a principal from the identity token that is not valid",
		path: "/api/v4/user/certificates", method: "post", status: 422,
		request: async () => await issueUser(newCa(), {}, { ...claims, groups: ["admins*"] }),
		errorPath: ["body"],
	},
	{
		name: "a request without tokens",
		path: "/api/v4/user/certificates", method: "post", status: 400,
		request: async () => await newCa().fetch(new Request("http://example.com/api/v4/user/certificates", { method: "POST", headers: { "Content-Type": "application/json" }, body: "{}" })),
	},
	{
		name: "a host principal that is not valid",
		path: "/api/v4/host/certificates", method: "post", status: 400,
		request: async () => await issueHost(newCa(), { principals: ["*"] }),
	},
	{
		name: "more than 256 user principals",
		path: "/api/v4/user/certificates", method: "post", status: 422,
		request: async () => await issueUser(newCa(), {}, { ...claims, groups: Array.from({ length: 256 }, (_, i) => `group${i}`) }),
		errorPath: ["body"],
	},
	{
		name: "more than 256 host principals",
		path: "/api/v4/host/certificates", method: "post", status: 400,
		request: async () => await issueHost(newCa(), { principals: Array.from({ length: 257 }, (_, i) => `host${i}.example.com`) }),
		errorPath: ["body", "principals"],
	},
	{
		name: "a CA key that cannot be parsed",
		path: "/api/v4/host/certificates", method: "post", status: 500,
		request: async () => await issueHost(newCa({ PRIVATE_KEY: secretFromString("not a key") })),
	},
]

describe("error responses match openapi.json", () => {
	it.each(cases)("$status for $name", async ({ path, method, status, request, errorPath }) => {
		const response = await request()
		expect(response.status).toBe(status)

		const body: unknown = await response.json()
		expect(mismatches(body, responseSchema(path, method, status))).toEqual([])

		if (errorPath !== undefined) {
			expect(body).toMatchObject({ errors: [{ path: errorPath }] })
		}
	})
})
