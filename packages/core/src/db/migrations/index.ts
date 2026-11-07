import type { Migration } from "../migrate.js"
import { migration as initialSchema0001 } from "./0001_initial_schema.js"
import { migration as krlVersion0002 } from "./0002_krl_version.js"
import { migration as krlRevision0003 } from "./0003_krl_revision.js"
import { migration as certificateAudit0004 } from "./0004_certificate_audit.js"
import { migration as renewalOf0005 } from "./0005_renewal_of.js"
import { migration as clientAddress0006 } from "./0006_client_address.js"

export const migrations: Migration[] = [
	initialSchema0001,
	krlVersion0002,
	krlRevision0003,
	certificateAudit0004,
	renewalOf0005,
	clientAddress0006,
]
