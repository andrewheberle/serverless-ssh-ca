import z from "zod"
import { CertificateType } from "../db/types.js"

/** The kinds of certificate, as they appear in admin UI paths */
export const CertificateKinds = ["user", "host"] as const

/** A kind of certificate, as it appears in admin UI paths */
export type CertificateKind = typeof CertificateKinds[number]

/**
 * Returns the type of certificate for a kind in an admin UI path.
 *
 * @param kind The kind of certificate
 * @returns The certificate type it is recorded as
 */
export const certificateType = (kind: CertificateKind): CertificateType => {
	switch (kind) {
		case "user":
			return CertificateType.User
		case "host":
			return CertificateType.Host
		default: {
			const unknown: never = kind
			throw new Error(`unknown certificate kind ${String(unknown)}`)
		}
	}
}

/**
 * Returns the path of the list of certificates of a kind.
 *
 * @param kind The kind of certificate
 * @returns The path, such as `/admin/user/certificates`
 */
export const certificatesPath = (kind: CertificateKind): string => `/admin/${kind}/certificates`

// the largest serial a certificate can have, as serials are 64-bit
const MaxSerial = (1n << 64n) - 1n

/**
 * A certificate serial in decimal, as shown in the admin UI, parsed to a
 * bigint. Leading zeros are allowed, so `007` is serial 7.
 */
export const SerialString = z.string().regex(/^\d{1,20}$/, { message: "must be a serial number in decimal" }).transform((v, ctx): bigint => {
	const serial = BigInt(v)
	if (serial > MaxSerial) {
		ctx.issues.push({ code: "custom", message: "must be a serial number in decimal", input: v })
		return z.NEVER
	}

	return serial
})

// a filter submitted by the filter form, which is trimmed and is not set when
// it is empty, as the form submits every field
const Filter = <T extends z.ZodType>(schema: T) => z.preprocess(
	(v) => typeof v === "string" && v.trim() === "" ? undefined : typeof v === "string" ? v.trim() : v,
	schema.optional(),
)

/**
 * The query parameters of a list of certificates, see `listCertificates`.
 * Parameters it does not name are ignored.
 */
export const CertificateListQuery = z.object({
	status: z.preprocess((v) => v === "" ? undefined : v, z.enum(["valid", "expired", "revoked", "all"]).default("valid")),
	// principals cannot contain a comma, which separates them where they are recorded
	principal: Filter(z.string().max(256).refine((v) => !v.includes(","), { message: "must not contain a comma" })),
	key_id: Filter(z.string().max(256)),
	serial: Filter(SerialString),
	before: Filter(z.string().regex(/^[1-9]\d{0,14}$/, { message: "must be a certificate ID" }).transform(Number)),
})

/** The validated query parameters of a list of certificates, see {@link CertificateListQuery} */
export type CertificateListQuery = z.infer<typeof CertificateListQuery>

/**
 * Returns the link to a list of certificates with the given filters, so the
 * filters are kept in the query string and a view can be bookmarked.
 *
 * @param kind The kind of certificate
 * @param query The filters and page
 * @returns The path and query string
 */
export const certificatesLink = (kind: CertificateKind, query: CertificateListQuery): string => {
	const params = new URLSearchParams({ status: query.status })
	if (query.principal !== undefined) {
		params.set("principal", query.principal)
	}
	if (query.key_id !== undefined) {
		params.set("key_id", query.key_id)
	}
	if (query.serial !== undefined) {
		params.set("serial", `${query.serial}`)
	}
	if (query.before !== undefined) {
		params.set("before", `${query.before}`)
	}

	return `${certificatesPath(kind)}?${params.toString()}`
}
