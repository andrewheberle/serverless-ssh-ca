import type { FC, PropsWithChildren } from "hono/jsx"
import type { CertificateDetails, CertificateStatus } from "../db/index.js"
import { PublicKey } from "../ssh/keys.js"
import { certificatesPath, type CertificateKind, type CertificateListQuery } from "./query.js"

/** The path the admin UI's stylesheet is served at */
export const StylesheetPath = "/admin/style.css"

/**
 * The stylesheet of the admin UI, served by the admin sub-app so the CSP can
 * allow styles from `'self'` only.
 */
export const Stylesheet = `:root {
	color-scheme: light dark;
	font-family: system-ui, sans-serif;
	line-height: 1.5;
}

body {
	margin: 0 auto;
	max-width: 72rem;
	padding: 1rem;
}

header {
	align-items: baseline;
	border-bottom: 1px solid currentColor;
	display: flex;
	flex-wrap: wrap;
	gap: 1rem;
	justify-content: space-between;
	margin-bottom: 1rem;
}

h1 {
	font-size: 1.25rem;
	margin: 0 0 0.5rem;
}

h2 {
	font-size: 1.125rem;
}

nav.tabs {
	display: flex;
	gap: 1rem;
	margin-bottom: 1rem;
}

nav.tabs a[aria-current="page"] {
	font-weight: bold;
}

form.filters {
	align-items: end;
	display: flex;
	flex-wrap: wrap;
	gap: 0.75rem;
	margin-bottom: 1rem;
}

form.filters label {
	display: flex;
	flex-direction: column;
	font-size: 0.875rem;
}

table {
	border-collapse: collapse;
	width: 100%;
}

th, td {
	border-bottom: 1px solid color-mix(in srgb, currentColor 25%, transparent);
	padding: 0.25rem 0.5rem;
	text-align: left;
	vertical-align: top;
}

dl {
	display: grid;
	gap: 0.25rem 1rem;
	grid-template-columns: max-content 1fr;
}

dt {
	font-weight: bold;
}

dd {
	margin: 0;
	overflow-wrap: anywhere;
}

ul.plain {
	list-style: none;
	margin: 0;
	padding: 0;
}

code {
	overflow-wrap: anywhere;
}
`

// shown for an audit value that was not recorded
const Unknown = "unknown"

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
			<header>
				<h1>SSH CA admin</h1>
				<p>Signed in as {email}</p>
			</header>
			<main>{children}</main>
		</body>
	</html>
)

/** A page explaining why a request could not be answered, such as a 400 or 404 */
export const ErrorPage: FC<{ email: string, title: string, message: string }> = ({ email, title, message }) => (
	<Layout title={title} email={email}>
		<h2>{title}</h2>
		<p>{message}</p>
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
		<form class="filters" method="get" action={certificatesPath(kind)}>
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
			<button type="submit">Filter</button>
		</form>
		{certificates.length === 0
			? <p>No certificates match.</p>
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
								<td><a href={`${certificatesPath(kind)}/${c.serial}`}>{c.serial}</a></td>
								<td>{c.key_id}</td>
								<td><Principals principals={c.principals} /></td>
								<td>{c.valid_after.toISOString()}</td>
								<td>{c.valid_before.toISOString()}</td>
								<td>{c.status}</td>
							</tr>
						))}
					</tbody>
				</table>
			)}
		{nextPage !== undefined && <p><a href={nextPage} rel="next">Next page</a></p>}
	</Layout>
)

/** The props of {@link CertificateDetailPage} */
export type CertificateDetailProps = {
	email: string
	kind: CertificateKind
	certificate: CertificateDetails
	status: CertificateStatus
}

/**
 * Everything recorded about one certificate. The revocation details are only
 * shown for a revoked certificate, and audit values that were not recorded
 * are shown as "unknown".
 */
export const CertificateDetailPage: FC<CertificateDetailProps> = ({ email, kind, certificate, status }) => {
	const extensions = certificate.extensions === null || certificate.extensions === "" ? [] : certificate.extensions.split(",")

	return (
		<Layout title={`${kindName(kind)} certificate ${certificate.serial}`} email={email}>
			<p><a href={certificatesPath(kind)}>Back to {kindName(kind).toLowerCase()} certificates</a></p>
			<h2>{kindName(kind)} certificate {certificate.serial}</h2>
			<dl>
				<dt>Serial</dt>
				<dd>{certificate.serial}</dd>
				<dt>Certificate type</dt>
				<dd>{kind}</dd>
				<dt>Key ID</dt>
				<dd>{certificate.key_id}</dd>
				<dt>Principals</dt>
				<dd><Principals principals={certificate.principals} /></dd>
				<dt>Extensions</dt>
				<dd>{extensions.length === 0 ? "none" : <ul class="plain">{extensions.map((e) => <li>{e}</li>)}</ul>}</dd>
				<dt>Valid from</dt>
				<dd>{certificate.valid_after.toISOString()}</dd>
				<dt>Valid until</dt>
				<dd>{certificate.valid_before.toISOString()}</dd>
				<dt>Status</dt>
				<dd>{status}</dd>
				<dt>Public key fingerprint</dt>
				<dd><code>{fingerprint(certificate.public_key) ?? Unknown}</code></dd>
				<dt>Requested by</dt>
				<dd>{certificate.requested_by ?? Unknown}</dd>
				{certificate.revoked_at !== null && (
					<>
						<dt>Revoked at</dt>
						<dd>{certificate.revoked_at.toISOString()}</dd>
						<dt>Revoked by</dt>
						<dd>{certificate.revoked_by ?? Unknown}</dd>
						<dt>Revocation reason</dt>
						<dd>{certificate.revocation_reason ?? Unknown}</dd>
					</>
				)}
			</dl>
		</Layout>
	)
}
