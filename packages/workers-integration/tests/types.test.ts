import type { SshCaBindings } from "@andrewheberle/serverless-ssh-ca"
import { describe, it, expectTypeOf } from "vitest"

// these assertions are enforced by the type check run before the tests
describe("package types", () => {
	it("accepts the wrangler generated Env as its bindings", () => {
		expectTypeOf<Env>().toExtend<SshCaBindings>()
	})
})
