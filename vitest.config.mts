import { defineConfig } from "vitest/config"

export default defineConfig(async () => {
	return {
		test: {
			coverage: {
				provider: "istanbul",
				include: ["src/**/*.ts"]
			}
		}
	}
})
