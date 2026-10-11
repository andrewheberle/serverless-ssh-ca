import type { Migration } from "../migrate.js"
import { migration as initialSchema0001 } from "./0001_initial_schema.js"
import { migration as krlVersion0002 } from "./0002_krl_version.js"

export const migrations: Migration[] = [
	initialSchema0001,
	krlVersion0002,
]
