import js from "@eslint/js"
import tseslint from "typescript-eslint"
import { defineConfig } from "eslint/config"

export default defineConfig([
    {
        ignores: ["dist/**", "tests/**", "scripts/**"],
    },
    {
        files: ["**/*.{js,mjs,cjs,ts,mts,cts,tsx}"],
        plugins: { js },
        extends: ["js/recommended"]
    },
    tseslint.configs.recommended,
    {
        // editors run one ESLint for the whole repository, so each package
        // names its own root rather than typescript-eslint guessing between them
        languageOptions: {
            parserOptions: { tsconfigRootDir: import.meta.dirname },
        },
    },
])
