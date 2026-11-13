import z from "zod"
import { MaxBulkRevocation } from "../db/index.js"
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
	status: z.preprocess((v) => v === "" ? undefined : v, z.enum(["valid", "expired", "revoked", "all"], { message: "must be Valid, Expired, Revoked or All" }).default("valid")),
	// principals cannot contain a comma, which separates them where they are recorded
	principal: Filter(z.string().max(256, { message: "must be at most 256 characters" }).refine((v) => !v.includes(","), { message: "must be a single principal, without a comma" })),
	key_id: Filter(z.string().max(256, { message: "must be at most 256 characters" })),
	serial: Filter(SerialString),
	before: Filter(z.string().regex(/^[1-9]\d{0,14}$/, { message: "is not a page of this list, so start again from the first page" }).transform(Number)),
})

// the names of the query parameters, as the filter form labels them
const QueryLabels: Record<string, string> = {
	status: "Status",
	principal: "Principal",
	key_id: "Key ID",
	serial: "Serial",
	before: "The page",
}

/**
 * Describes why the query parameters of a list of certificates are not
 * valid, one sentence per problem, naming each parameter as the filter form
 * labels it.
 *
 * @param error The error from parsing {@link CertificateListQuery}
 * @returns The problems, such as "Status must be Valid, Expired, Revoked or All."
 */
export const describeQueryError = (error: z.ZodError): string[] => error.issues.map((issue) => {
	const name = typeof issue.path[0] === "string" ? QueryLabels[issue.path[0]] : undefined
	return `${name ?? "A filter"} ${issue.message}.`
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

/** The longest reason an admin may give for revoking a certificate */
export const MaxRevocationReason = 500

/**
 * The form an admin revokes a certificate with. The reason is trimmed and
 * must then be 1 to {@link MaxRevocationReason} characters, and the
 * confirmation box must be ticked. Each message is shown to the admin as it
 * is.
 */
export const RevokeForm = z.object({
	// a form sends each line break as CRLF, but the browser counts it as one
	// character against the textarea's maxlength, so the reason is counted,
	// and recorded, with LF line breaks
	reason: z.string({ message: "Give a reason for revoking the certificate." })
		.transform((v) => v.replaceAll("\r\n", "\n"))
		.pipe(z.string()
			.trim()
			.min(1, { message: "Give a reason for revoking the certificate." })
			.max(MaxRevocationReason, { message: `The reason must be at most ${MaxRevocationReason} characters.` })),
	confirm: z.literal("yes", { message: "Tick the box to confirm that the revocation cannot be undone." }),
})

/** A validated revoke form, see {@link RevokeForm} */
export type RevokeForm = z.infer<typeof RevokeForm>

/**
 * The filters of a list of certificates that may be revoked together: only
 * valid certificates, narrowed by a principal or key ID, so every valid
 * certificate is never one click away. A serial filter alone matches one
 * certificate at most, which its own revoke form covers.
 */
export type BulkRevocationFilters = {
	principal?: string | undefined
	key_id?: string | undefined
	serial?: bigint | undefined
}

/**
 * Returns the filters of a list of certificates if its certificates may be
 * revoked together, see {@link BulkRevocationFilters}.
 *
 * @param query The filters of the list
 * @returns The filters, or undefined if the list may not be revoked together
 */
export const bulkRevocationFilters = (query: CertificateListQuery): BulkRevocationFilters | undefined => {
	if (query.status !== "valid" || (query.principal === undefined && query.key_id === undefined)) {
		return undefined
	}

	return { principal: query.principal, key_id: query.key_id, serial: query.serial }
}

/**
 * Returns the path of the page that confirms revoking certificates of a kind
 * together, and that its form is sent to.
 *
 * @param kind The kind of certificate
 * @returns The path, such as `/admin/user/certificates/revoke`
 */
export const bulkRevokePath = (kind: CertificateKind): string => `${certificatesPath(kind)}/revoke`

/**
 * Returns the link to the page that confirms revoking the certificates that
 * match filters, see {@link bulkRevocationFilters}.
 *
 * @param kind The kind of certificate
 * @param filters The filters
 * @returns The path and query string
 */
export const bulkRevokeLink = (kind: CertificateKind, filters: BulkRevocationFilters): string => {
	// the list's own link, without the page, as the same filters are used
	const list = certificatesLink(kind, { status: "valid", principal: filters.principal, key_id: filters.key_id, serial: filters.serial, before: undefined })
	return `${bulkRevokePath(kind)}${list.slice(certificatesPath(kind).length)}`
}

// the message for a selected serial that is not a serial
const NotASerial = "A selected certificate is not a valid serial number."

/**
 * The values of a form field that may be sent several times, as Hono's
 * `parseBody({ all: true })` gives them: none, one, or an array.
 *
 * @param value The field's value
 * @returns The values
 */
export const formValues = (value: unknown): unknown[] => value === undefined ? [] : Array.isArray(value) ? value : [value]

/**
 * The form an admin revokes several certificates of one kind with, see
 * {@link RevokeForm}: a `serial` field for each certificate that is ticked,
 * at most {@link MaxBulkRevocation}, one reason for them all and the
 * confirmation. The `principal`, `key_id` and serial filters the
 * certificates were found with are sent back so the admin can be returned to
 * the list; the serial filter is sent as `filter_serial`, as `serial` names
 * the ticked certificates. Each message is shown to the admin as it is.
 */
export const BulkRevokeForm = z.object({
	serial: z.preprocess(formValues, z.array(z.string({ message: NotASerial }).pipe(SerialString))
		.min(1, { message: "Select at least one certificate to revoke." })
		.max(MaxBulkRevocation, { message: `At most ${MaxBulkRevocation} certificates can be revoked at once.` })),
	reason: RevokeForm.shape.reason,
	confirm: RevokeForm.shape.confirm,
	principal: CertificateListQuery.shape.principal,
	key_id: CertificateListQuery.shape.key_id,
	filter_serial: CertificateListQuery.shape.serial,
})

/**
 * The filters a bulk revoke form was sent with, see {@link BulkRevokeForm},
 * or none when they are not valid.
 *
 * @param body The form as it was sent
 * @returns The filters
 */
export const bulkRevokeFormFilters = (body: unknown): BulkRevocationFilters => {
	const filters = BulkRevokeForm.pick({ principal: true, key_id: true, filter_serial: true }).safeParse(body)
	return filters.success ? { principal: filters.data.principal, key_id: filters.data.key_id, serial: filters.data.filter_serial } : {}
}

/** The fields of a revoke form, see {@link RevokeForm} and {@link BulkRevokeForm} */
export type RevokeFormField = "reason" | "confirm" | "serial"

/**
 * Returns the fields of a revoke form that are not valid, so each can be
 * marked as invalid where it is shown.
 *
 * @param error The error from parsing {@link RevokeForm} or {@link BulkRevokeForm}
 * @returns The fields with at least one problem
 */
export const invalidRevokeFields = (error: z.ZodError): RevokeFormField[] => {
	const fields = new Set(error.issues.map((issue) => issue.path[0]))
	return (["reason", "confirm", "serial"] as const).filter((field) => fields.has(field))
}

/** A validated bulk revoke form, see {@link BulkRevokeForm} */
export type BulkRevokeForm = z.infer<typeof BulkRevokeForm>

/**
 * Describes why a bulk revoke form is not valid, once for each problem.
 *
 * @param error The error from parsing {@link BulkRevokeForm}
 * @returns The problems, as they are shown to the admin
 */
export const describeBulkRevokeError = (error: z.ZodError): string[] => [...new Set(error.issues.map((issue) => {
	const [field] = issue.path
	if (field === "serial" && issue.path.length > 1) {
		return NotASerial
	}
	if (field === "principal" || field === "key_id") {
		return `${QueryLabels[field]} ${issue.message}.`
	}
	if (field === "filter_serial") {
		return `${QueryLabels.serial} ${issue.message}.`
	}

	return issue.message
}))]
