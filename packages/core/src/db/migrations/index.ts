import type { Migration } from "../migrate.js"
import { migration as initialSchema0001 } from "./0001_initial_schema.js"
import { migration as krlVersion0002 } from "./0002_krl_version.js"
import { migration as krlRevision0003 } from "./0003_krl_revision.js"

export const migrations: Migration[] = [
	initialSchema0001,
	krlVersion0002,
	krlRevision0003,
]
