import { type Migration } from "workers-qb"
import { migration as initialSchema0001 } from "./0001_initial_schema"

export const migrations: Migration[] = [
	initialSchema0001
]
