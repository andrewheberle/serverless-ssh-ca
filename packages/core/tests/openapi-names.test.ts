import { describe, it, expect } from "vitest"
import { ApiVersion, createApp } from "../src/router.js"
import { makeEnv } from "./env.js"
import openapi from "../openapi.json" with { type: "json" }

// Clients generate code from openapi.json, so the operation IDs and component
// names are part of the contract: renaming one breaks the client's generated
// code although oasdiff reports it only as INFO. Changing either list here is
// a breaking change, and needs a major bump of ApiVersion (see its TSDoc) and
// a major release (#610)

const operationIds = [
	"get_ca_public_key",
	"get_host_revocation_list",
	"get_user_revocation_list",
	"issue_host_certificate",
	"issue_user_certificate",
	"renew_host_certificate",
	"revoke_host_certificate",
	"revoke_user_certificate",
]

const componentNames = [
	"Certificate Response",
	"Host Certificate Issue Request",
	"Host Certificate Renewal Request",
	"Key Revocation List Response",
	"Revocation Response",
	"User Certificate Issue Request",
]

type Schema = {
	info: { version: string }
	paths: Record<string, Record<string, { operationId?: string }>>
	components?: { schemas?: Record<string, unknown> }
}

// the generated schema, and the committed one clients are built from
const schemas: [string, Schema][] = [
	["generated", createApp(makeEnv()).schema as Schema],
	["committed", openapi as Schema],
]

describe.each(schemas)("the %s openapi.json", (_name, schema) => {
	it("should have the pinned operation IDs", () => {
		const ids = Object.values(schema.paths).flatMap((operations) => Object.values(operations).map((operation) => operation.operationId))

		expect(ids.toSorted(), "renaming an operation ID is a breaking change, see ApiVersion").toEqual(operationIds)
	})

	it("should have the pinned component names", () => {
		expect(Object.keys(schema.components?.schemas ?? {}).toSorted(), "renaming a component is a breaking change, see ApiVersion").toEqual(componentNames)
	})

	it("should publish ApiVersion as info.version", () => {
		expect(schema.info.version).toBe(ApiVersion)
	})
})
