import type { Migration } from "../migrate.js"
import { migration as initialSchema0001 } from "./0001_initial_schema.js"

export const migrations: Migration[] = [
	initialSchema0001
]
