import { defineConfig } from "vitest/config"

// runs the built command under each runtime, so needs "npm run build" first
export default defineConfig({
	test: {
		include: ["integration/**/*.test.ts"],
		testTimeout: 120_000,
		hookTimeout: 120_000,
	},
})
