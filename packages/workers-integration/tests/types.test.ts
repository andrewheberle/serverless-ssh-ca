import type { CaDatabase, CaSecret, SshCaBindings } from "@andrewheberle/serverless-ssh-ca"
import { describe, it, expectTypeOf } from "vitest"

// these assertions are enforced by the type check run before the tests
describe("package types", () => {
	it("accepts the wrangler generated Env as its bindings", () => {
		expectTypeOf<Env>().toExtend<SshCaBindings>()
	})

	it("accepts a D1 binding as its database", () => {
		expectTypeOf<D1Database>().toExtend<CaDatabase>()
	})

	it("accepts a Secrets Store binding as its secret", () => {
		expectTypeOf<SecretsStoreSecret>().toExtend<CaSecret>()
	})
})
