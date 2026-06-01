import { defineConfig } from "vitest/config"

export default defineConfig(async () => {
	return {
		test: {
			globalSetup: ["./tests/setup/oidc-server.ts"],
			coverage: {
				include: ["src/**/*.ts"]
			}
		}
	}
})
