import { defineConfig } from "vitest/config"

export default defineConfig(async () => {
	return {
		test: {
			coverage: {
				include: ["src/**/*.ts"]
			}
		}
	}
})
