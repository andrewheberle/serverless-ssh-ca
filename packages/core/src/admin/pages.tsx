import type { FC, PropsWithChildren } from "hono/jsx"
import type { CertificateDetails, CertificateStatus, RenewalLinks, RenewalOf } from "../db/index.js"
import { PublicKey } from "../ssh/keys.js"
import { BaseStylesheet } from "../web/styles.js"
import { certificatesPath, MaxRevocationReason, type CertificateKind, type CertificateListQuery } from "./query.js"

/** The path the admin UI's stylesheet is served at */
export const StylesheetPath = "/admin/style.css"

/**
 * The stylesheet of the admin UI, the styles shared with the CA's other
 * pages (see {@link BaseStylesheet}) followed by the admin UI's own, served
 * by the admin sub-app so the CSP can allow styles from `'self'` only.
 */
export const Stylesheet = `${BaseStylesheet}
.site-header {
	background: var(--base);
	border-bottom: 1px solid var(--hairline);
}

.site-header > div {
	align-items: center;
	display: flex;
	flex-wrap: wrap;
	gap: 0.5rem 1rem;
	justify-content: space-between;
	margin: 0 auto;
	max-width: 80rem;
	padding: 0.75rem 1.5rem;
}

.site-header h1 {
	color: var(--text-strong);
	font-size: 1rem;
	font-weight: 600;
	margin: 0;
}

.site-header p {
	color: var(--text-subtle);
	font-size: 0.875rem;
	margin: 0;
}

main {
	display: flex;
	flex-direction: column;
	gap: 1rem;
	margin: 0 auto;
	max-width: 80rem;
	padding: 1.5rem;
}

.page-heading {
	align-items: center;
	display: flex;
	flex-wrap: wrap;
	gap: 0.75rem;
}

.card.flush {
	overflow-x: auto;
	padding: 0;
}

.tabs {
	align-self: flex-start;
	background: var(--recessed);
	border-radius: 0.5rem;
	display: flex;
	gap: 0.125rem;
	padding: 0.125rem;
}

.tabs a {
	border-radius: 0.375rem;
	color: var(--text-subtle);
	font-size: 0.875rem;
	padding: 0.25rem 0.75rem;
}

.tabs a:hover {
	background: var(--tint);
	color: var(--text);
	text-decoration: none;
}

.tabs a[aria-current="page"] {
	background: var(--base);
	box-shadow: 0 0 0 1px var(--line), 0 1px 2px oklch(0% 0 0 / 0.06);
	color: var(--text);
	font-weight: 500;
}

.filters {
	align-items: end;
	display: grid;
	gap: 0.75rem;
	grid-template-columns: repeat(auto-fit, minmax(10rem, 1fr));
}

.filters .button {
	justify-self: start;
	min-width: 6rem;
}

.filters label {
	color: var(--text-strong);
	display: grid;
	font-size: 0.8125rem;
	font-weight: 500;
	gap: 0.375rem;
}

input, select, .button {
	border: 0;
	border-radius: 0.5rem;
	font: inherit;
	font-size: 0.875rem;
	height: 2.25rem;
	margin: 0;
	padding: 0 0.75rem;
}

input, select {
	background: var(--control);
	box-shadow: 0 0 0 1px var(--line);
	color: var(--text);
	width: 100%;
}

input:focus, select:focus {
	box-shadow: 0 0 0 1.5px var(--focus);
	outline: none;
}

.button {
	align-items: center;
	background: var(--base);
	box-shadow: 0 0 0 1px var(--line);
	color: var(--text);
	cursor: pointer;
	display: inline-flex;
	font-weight: 500;
	justify-content: center;
	white-space: nowrap;
}

.button:hover {
	background: var(--tint);
	text-decoration: none;
}

.button.primary {
	background: var(--brand);
	box-shadow: none;
	color: #fff;
}

.button.primary:hover {
	background: color-mix(in oklch, var(--brand), black 10%);
}

table {
	border-collapse: collapse;
	font-size: 0.875rem;
	width: 100%;
}

th {
	background: var(--elevated);
	border-bottom: 1px solid var(--fill);
	color: var(--text-strong);
	font-size: 0.75rem;
	font-weight: 600;
	padding: 0.5rem 0.75rem;
	text-align: left;
	white-space: nowrap;
}

td {
	border-bottom: 1px solid var(--hairline);
	padding: 0.625rem 0.75rem;
	vertical-align: top;
}

tbody tr:last-child td {
	border-bottom: 0;
}

tbody tr:hover td {
	background: var(--tint);
}

td time {
	white-space: nowrap;
}

.badge {
	align-items: center;
	border-radius: 999px;
	display: inline-flex;
	font-size: 0.75rem;
	font-weight: 500;
	padding: 0.125rem 0.5rem;
	white-space: nowrap;
}

.badge.valid {
	background: var(--success-tint);
	color: var(--success);
}

.badge.expired {
	background: var(--fill);
	color: var(--neutral);
}

.badge.revoked {
	background: var(--danger-tint);
	color: var(--danger);
}

.empty {
	color: var(--text-subtle);
	margin: 0;
	padding: 2rem 1rem;
	text-align: center;
}

.pager {
	display: flex;
	justify-content: flex-end;
}

.details {
	display: grid;
	font-size: 0.875rem;
	gap: 0;
	grid-template-columns: minmax(8rem, 12rem) 1fr;
	margin: 0;
}

.details dt, .details dd {
	border-bottom: 1px solid var(--hairline);
	padding: 0.625rem 0;
}

.details dt {
	color: var(--text-subtle);
	padding-right: 1rem;
}

.details dd {
	margin: 0;
	overflow-wrap: anywhere;
}

.details dt:last-of-type, .details dd:last-of-type {
	border-bottom: 0;
}

.section-title {
	color: var(--text-strong);
	font-size: 0.875rem;
	font-weight: 600;
	margin: 0 0 0.25rem;
}

ul.plain {
	list-style: none;
	margin: 0;
	padding: 0;
}

.alert {
	background: var(--danger-tint);
	border-radius: 0.5rem;
	box-shadow: 0 0 0 1px color-mix(in oklch, var(--danger), transparent 75%);
	padding: 1rem;
}

.alert h2 {
	color: var(--danger);
	font-size: 1rem;
	margin-bottom: 0.25rem;
}

.alert p, .alert ul {
	margin: 0.25rem 0 0;
}

.unknown {
	color: var(--text-subtle);
	font-style: italic;
}

.revoke {
	display: grid;
	gap: 0.75rem;
}

.revoke p {
	color: var(--text-subtle);
	font-size: 0.875rem;
	margin: 0;
}

.revoke label {
	color: var(--text-strong);
	display: grid;
	font-size: 0.8125rem;
	font-weight: 500;
	gap: 0.375rem;
}

.revoke label.checkbox {
	align-items: center;
	display: flex;
	font-weight: 400;
	gap: 0.5rem;
}

textarea {
	background: var(--control);
	border: 0;
	border-radius: 0.5rem;
	box-shadow: 0 0 0 1px var(--line);
	color: var(--text);
	font: inherit;
	font-size: 0.875rem;
	min-height: 5rem;
	padding: 0.5rem 0.75rem;
	resize: vertical;
	width: 100%;
}

textarea:focus {
	box-shadow: 0 0 0 1.5px var(--focus);
	outline: none;
}

textarea[aria-invalid="true"] {
	box-shadow: 0 0 0 1.5px var(--danger);
}

input[type="checkbox"] {
	accent-color: var(--danger);
	box-shadow: none;
	height: 1rem;
	padding: 0;
	width: 1rem;
}

.button.danger {
	background: var(--danger);
	box-shadow: none;
	color: #fff;
	justify-self: start;
}

.button.danger:hover {
	background: color-mix(in oklch, var(--danger), black 10%);
}

.form-errors {
	color: var(--danger);
	font-size: 0.875rem;
	margin: 0;
	padding-left: 1.25rem;
}
`

// shown for an audit value that was not recorded
const Unknown: FC = () => <span class="unknown">unknown</span>

/**
 * Formats a time in UTC for people to read, such as `2026-11-04 21:10 UTC`,
 * or to the second, such as `2026-11-04 21:10:54 UTC`.
 *
 * @param date The time
 * @param precision Whether to show minutes or seconds
 * @returns The formatted time
 */
export const formatTimestamp = (date: Date, precision: "minute" | "second"): string => {
	const iso = date.toISOString()
	return `${iso.slice(0, 10)} ${iso.slice(11, precision === "minute" ? 16 : 19)} UTC`
}

// a time, readable on the page and exact in its datetime attribute
const Timestamp: FC<{ date: Date, precision: "minute" | "second" }> = ({ date, precision }) => (
	<time datetime={date.toISOString()}>{formatTimestamp(date, precision)}</time>
)

// the label of each status, as shown in a badge
const StatusLabels: Record<CertificateStatus, string> = {
	valid: "Valid",
	expired: "Expired",
	revoked: "Revoked",
}

// the status of a certificate, as a coloured badge
const StatusBadge: FC<{ status: CertificateStatus }> = ({ status }) => (
	<span class={`badge ${status}`}>{StatusLabels[status]}</span>
)

/**
 * The page every admin UI page is rendered in, which shows who is signed in.
 * Values are escaped by JSX, so nothing passed to it is ever treated as HTML.
 */
export const Layout: FC<PropsWithChildren<{ title: string, email: string }>> = ({ title, email, children }) => (
	<html lang="en">
		<head>
			<meta charset="utf-8" />
			<meta name="viewport" content="width=device-width, initial-scale=1" />
			<title>{title} - SSH CA admin</title>
			<link rel="stylesheet" href={StylesheetPath} />
		</head>
		<body>
			<header class="site-header">
				<div>
					<h1>SSH CA admin</h1>
					<p>Signed in as {email}</p>
				</div>
			</header>
			<main>{children}</main>
		</body>
	</html>
)

/**
 * A page explaining why a request could not be answered, such as a 400 or
 * 404, with a list of the problems when there are several.
 */
export const ErrorPage: FC<{ email: string, title: string, message: string, problems?: string[] }> = ({ email, title, message, problems = [] }) => (
	<Layout title={title} email={email}>
		<div class="alert" role="alert">
			<h2>{title}</h2>
			<p>{message}</p>
			{problems.length > 0 && <ul>{problems.map((p) => <li>{p}</li>)}</ul>}
		</div>
		<p><a href={certificatesPath("user")}>Back to certificates</a></p>
	</Layout>
)

// the name of a kind of certificate, for headings
const kindName = (kind: CertificateKind): string => kind === "user" ? "User" : "Host"

/**
 * Returns the principals of a certificate without the `UID=` or `CN=` prefix
 * they are recorded with.
 *
 * @param principals The principals as recorded, such as `UID=alice,UID=bob`
 * @returns The principals, such as `["alice", "bob"]`
 */
export const displayPrincipals = (principals: string): string[] => principals === ""
	? []
	: principals.split(",").map((p) => p.replace(/^(UID|CN)=/, ""))

// the SHA256 fingerprint of a recorded public key, if it has one that can be parsed
const fingerprint = (publicKey: string | null): string | undefined => {
	if (publicKey === null) {
		return undefined
	}

	try {
		return PublicKey.parse(publicKey).fingerprint()
	} catch {
		return undefined
	}
}

const Principals: FC<{ principals: string }> = ({ principals }) => {
	const list = displayPrincipals(principals)
	if (list.length === 0) {
		return <>none</>
	}

	return <ul class="plain">{list.map((p) => <li>{p}</li>)}</ul>
}

const StatusOptions: { value: CertificateListQuery["status"], label: string }[] = [
	{ value: "valid", label: "Valid" },
	{ value: "expired", label: "Expired" },
	{ value: "revoked", label: "Revoked" },
	{ value: "all", label: "All" },
]

/** The props of {@link CertificateListPage} */
export type CertificateListProps = {
	email: string
	kind: CertificateKind
	query: CertificateListQuery
	certificates: (CertificateDetails & { status: CertificateStatus })[]
	/** The link to the next page, if there is one */
	nextPage: string | undefined
}

/**
 * The list of certificates of one kind, with tabs for each kind, a form of
 * filters kept in the query string, and a link to the next page.
 */
export const CertificateListPage: FC<CertificateListProps> = ({ email, kind, query, certificates, nextPage }) => (
	<Layout title={`${kindName(kind)} certificates`} email={email}>
		<nav class="tabs" aria-label="Certificate type">
			{(["user", "host"] as const).map((k) => (
				<a href={certificatesPath(k)} aria-current={k === kind ? "page" : undefined}>{kindName(k)} certificates</a>
			))}
		</nav>
		<h2>{kindName(kind)} certificates</h2>
		<form class="filters card" method="get" action={certificatesPath(kind)}>
			<label>
				Status
				<select name="status">
					{StatusOptions.map((o) => <option value={o.value} selected={o.value === query.status}>{o.label}</option>)}
				</select>
			</label>
			<label>
				Principal
				<input type="text" name="principal" value={query.principal ?? ""} />
			</label>
			<label>
				Key ID
				<input type="text" name="key_id" value={query.key_id ?? ""} />
			</label>
			<label>
				Serial
				<input type="text" name="serial" inputmode="numeric" value={query.serial === undefined ? "" : `${query.serial}`} />
			</label>
			<button type="submit" class="button primary">Filter</button>
		</form>
		<div class="card flush">
			{certificates.length === 0
				? <p class="empty">No certificates match these filters.</p>
				: (
					<table>
						<thead>
							<tr>
								<th scope="col">Serial</th>
								<th scope="col">Key ID</th>
								<th scope="col">Principals</th>
								<th scope="col">Valid from</th>
								<th scope="col">Valid until</th>
								<th scope="col">Status</th>
							</tr>
						</thead>
						<tbody>
							{certificates.map((c) => (
								<tr>
									<td class="mono"><a href={`${certificatesPath(kind)}/${c.serial}`}>{c.serial}</a></td>
									<td>{c.key_id}</td>
									<td><Principals principals={c.principals} /></td>
									<td><Timestamp date={c.valid_after} precision="minute" /></td>
									<td><Timestamp date={c.valid_before} precision="minute" /></td>
									<td><StatusBadge status={c.status} /></td>
								</tr>
							))}
						</tbody>
					</table>
				)}
		</div>
		{nextPage !== undefined && <div class="pager"><a class="button" href={nextPage} rel="next">Next page</a></div>}
	</Layout>
)

/** The props of {@link CertificateDetailPage} */
export type CertificateDetailProps = {
	email: string
	kind: CertificateKind
	certificate: CertificateDetails
	status: CertificateStatus
	/** The certificates it is linked to by renewal, see {@link RenewalLinks} */
	renewal: RenewalLinks
	/** The revoke form as it was sent, when it is shown again because it was not valid */
	revokeForm?: { reason: string, errors: string[] } | undefined
}

/**
 * The form an admin revokes a valid certificate with, which asks for a
 * reason and a confirmation as a revocation cannot be undone. When it is
 * shown again it keeps the reason that was entered and lists what was wrong.
 */
const RevokeSection: FC<{ kind: CertificateKind, serial: string, form: CertificateDetailProps["revokeForm"] }> = ({ kind, serial, form }) => {
	const errors = form?.errors ?? []

	return (
		<section class="card">
			<h3 class="section-title">Revoke this certificate</h3>
			<form class="revoke" method="post" action={`${certificatesPath(kind)}/${serial}/revoke`}>
				<p>Revoking is permanent and cannot be undone. The certificate is added to the {kind} KRL until it expires, and access is restored by issuing a new certificate.</p>
				{errors.length > 0 && <ul class="form-errors" role="alert">{errors.map((e) => <li>{e}</li>)}</ul>}
				<label>
					Reason
					<textarea name="reason" required maxlength={MaxRevocationReason} aria-invalid={errors.length > 0 ? "true" : undefined}>{form?.reason ?? ""}</textarea>
				</label>
				<label class="checkbox">
					<input type="checkbox" name="confirm" value="yes" required />
					I understand that this revocation cannot be undone
				</label>
				<button type="submit" class="button danger">Revoke certificate</button>
			</form>
		</section>
	)
}

// a link to a certificate of the same kind
const CertificateLink: FC<{ kind: CertificateKind, serial: string }> = ({ kind, serial }) =>
	<a class="mono" href={`${certificatesPath(kind)}/${serial}`}>{serial}</a>

// the certificate a renewal renewed, which is only linked to while it is
// still recorded
const RenewalOfValue: FC<{ kind: CertificateKind, renewalOf: RenewalOf }> = ({ kind, renewalOf }) => {
	switch (renewalOf.kind) {
		case "recorded":
			return <CertificateLink kind={kind} serial={renewalOf.serial} />
		case "notRecorded":
			return <><span class="mono">{renewalOf.serial}</span> <span class="unknown">(no longer recorded)</span></>
		default: {
			const unknown: never = renewalOf
			throw new Error(`unknown renewal ${JSON.stringify(unknown)}`)
		}
	}
}

/**
 * Everything recorded about one certificate. The revocation details are only
 * shown for a revoked certificate, and audit values that were not recorded
 * are shown as "unknown". A renewal has no requester, and links to the
 * certificate it is a renewal of, while a certificate revoked for renewal
 * links to the certificate that renewed it. A valid certificate has a form to
 * revoke it, while revoked and expired certificates are read-only.
 */
export const CertificateDetailPage: FC<CertificateDetailProps> = ({ email, kind, certificate, status, renewal, revokeForm }) => {
	const extensions = certificate.extensions === null || certificate.extensions === "" ? [] : certificate.extensions.split(",")
	const keyFingerprint = fingerprint(certificate.public_key)

	return (
		<Layout title={`${kindName(kind)} certificate ${certificate.serial}`} email={email}>
			<p><a href={certificatesPath(kind)}>Back to {kindName(kind).toLowerCase()} certificates</a></p>
			<div class="page-heading">
				<h2>{kindName(kind)} certificate <span class="mono">{certificate.serial}</span></h2>
				<StatusBadge status={status} />
			</div>
			<section class="card">
				<dl class="details">
					<dt>Serial</dt>
					<dd class="mono">{certificate.serial}</dd>
					<dt>Certificate type</dt>
					<dd>{kind}</dd>
					<dt>Key ID</dt>
					<dd>{certificate.key_id}</dd>
					<dt>Principals</dt>
					<dd><Principals principals={certificate.principals} /></dd>
					<dt>Extensions</dt>
					<dd>{extensions.length === 0 ? "none" : <ul class="plain">{extensions.map((e) => <li>{e}</li>)}</ul>}</dd>
					<dt>Valid from</dt>
					<dd><Timestamp date={certificate.valid_after} precision="second" /></dd>
					<dt>Valid until</dt>
					<dd><Timestamp date={certificate.valid_before} precision="second" /></dd>
					<dt>Status</dt>
					<dd><StatusBadge status={status} /></dd>
					<dt>Public key fingerprint</dt>
					<dd>{keyFingerprint === undefined ? <Unknown /> : <code>{keyFingerprint}</code>}</dd>
					<dt>Requested by</dt>
					<dd>{certificate.requested_by ?? (renewal.renewalOf === undefined ? <Unknown /> : <span class="unknown">none (renewal)</span>)}</dd>
					{renewal.renewalOf !== undefined && <>
						<dt>Renewal of</dt>
						<dd><RenewalOfValue kind={kind} renewalOf={renewal.renewalOf} /></dd>
					</>}
				</dl>
			</section>
			{certificate.revoked_at !== null && (
				<section class="card">
					<h3 class="section-title">Revocation</h3>
					<dl class="details">
						<dt>Revoked at</dt>
						<dd><Timestamp date={certificate.revoked_at} precision="second" /></dd>
						<dt>Revoked by</dt>
						<dd>{certificate.revoked_by ?? <Unknown />}</dd>
						<dt>Revocation reason</dt>
						<dd>{certificate.revocation_reason ?? <Unknown />}</dd>
						{(renewal.renewedAs !== undefined || certificate.revocation_reason === "renewal") && <>
							<dt>Renewed as</dt>
							<dd>{renewal.renewedAs === undefined ? <Unknown /> : <CertificateLink kind={kind} serial={renewal.renewedAs} />}</dd>
						</>}
					</dl>
				</section>
			)}
			{status === "valid" && <RevokeSection kind={kind} serial={certificate.serial} form={revokeForm} />}
		</Layout>
	)
}
