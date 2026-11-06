import type { FC, PropsWithChildren } from "hono/jsx"
import { BaseStylesheet } from "../web/styles.js"

/** The path the landing page's stylesheet is served at */
export const LandingStylesheetPath = "/style.css"

/** The ssh-ca-client repository, which users and hosts request certificates with */
export const ClientRepositoryUrl = "https://github.com/andrewheberle/ssh-ca-client"

/**
 * The stylesheet of the landing page, the styles shared with the CA's other
 * pages (see {@link BaseStylesheet}) followed by the landing page's own
 * layout: a centred hero with the padlock in a round tinted badge, cards
 * below it and a muted monospace footer, after the page ssh-ca-client shows
 * at the end of its login flow.
 */
export const LandingStylesheet = `${BaseStylesheet}
body {
	padding-inline: 16px;
}

main {
	display: flex;
	flex-direction: column;
	gap: 1rem;
	margin: 0 auto;
	max-width: 48rem;
	padding: 2.5rem 0 1.5rem;
}

.hero {
	display: grid;
	gap: 0.75rem;
	justify-items: center;
	padding-bottom: 0.5rem;
	text-align: center;
}

.hero h1 {
	color: var(--text-strong);
	font-size: 1.5rem;
	font-weight: 600;
	margin: 0.25rem 0 0;
	text-wrap: balance;
}

.hero p {
	color: var(--text-subtle);
	margin: 0;
	max-width: 36rem;
}

.icon {
	background: color-mix(in oklch, var(--brand), transparent 88%);
	border-radius: 50%;
	color: var(--brand);
	display: grid;
	height: 3rem;
	place-items: center;
	width: 3rem;
}

.card {
	display: grid;
	gap: 0.75rem;
	padding: 1.25rem;
}

.card h2 {
	font-size: 1.0625rem;
}

.card h3 {
	color: var(--text-strong);
	font-size: 0.9375rem;
	font-weight: 600;
	margin: 0.25rem 0 0;
}

.card p {
	margin: 0;
}

.subtle {
	color: var(--text-subtle);
	font-size: 0.875rem;
}

pre {
	background: var(--recessed);
	border-radius: 0.5rem;
	box-shadow: 0 0 0 1px var(--hairline);
	font-family: var(--mono);
	font-size: 0.8125rem;
	margin: 0;
	overflow-x: auto;
	padding: 0.75rem 1rem;
}

pre code {
	font-size: inherit;
	overflow-wrap: normal;
}

pre.key {
	white-space: pre-wrap;
	word-break: break-all;
}

ul.links {
	display: grid;
	gap: 0.375rem;
	margin: 0;
	padding-left: 1.25rem;
}

footer {
	border-top: 1px solid var(--hairline);
	color: var(--text-subtle);
	font-family: var(--mono);
	font-size: 0.75rem;
	letter-spacing: 0.02em;
	margin-top: 0.5rem;
	padding-top: 0.75rem;
	text-align: center;
}
`

/**
 * What the landing page shows, all of which the CA already publishes.
 */
export interface LandingPageProps {
	/** The origin the CA was requested on, such as `https://ssh-ca.example.com`, used only in the copyable snippets */
	origin: string
	/** The CA public key in OpenSSH format */
	publicKey: string
	/** The SHA256 fingerprint of the CA public key */
	fingerprint: string
	/** The link to the admin UI, when it is turned on */
	adminUrl: string | undefined
}

// a padlock, drawn like the icons of the page ssh-ca-client shows at the end
// of its login flow
const Padlock: FC = () => (
	<svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.25" stroke-linecap="round" stroke-linejoin="round">
		<rect x="5" y="11" width="14" height="10" rx="2" />
		<path d="M8 11V7a4 4 0 0 1 8 0v4" />
	</svg>
)

// a snippet to copy, such as a command or configuration
const Snippet: FC<{ lines: string[] }> = ({ lines }) => <pre><code>{lines.join("\n")}</code></pre>

// a card with a heading
const Section: FC<PropsWithChildren<{ id: string, title: string }>> = ({ id, title, children }) => (
	<section class="card" aria-labelledby={id}>
		<h2 id={id}>{title}</h2>
		{children}
	</section>
)

/**
 * The landing page, which shows the CA public key, generic setup
 * instructions for hosts and clients, and links to what else the CA
 * publishes. It never shows the identity provider's settings, as the CA
 * cannot know all of the client's for certain. Values are escaped by JSX, so
 * nothing passed to it is ever treated as HTML.
 */
export const LandingPage: FC<LandingPageProps> = ({ origin, publicKey, fingerprint, adminUrl }) => (
	<html lang="en">
		<head>
			<meta charset="utf-8" />
			<meta name="viewport" content="width=device-width, initial-scale=1" />
			<title>SSH Certificate Authority</title>
			<link rel="stylesheet" href={LandingStylesheetPath} />
		</head>
		<body>
			<main>
				<header class="hero">
					<div class="icon" aria-hidden="true"><Padlock /></div>
					<h1>SSH Certificate Authority</h1>
					<p>This service signs SSH certificates for users and hosts. Use the details below to trust its certificates and to request your own.</p>
				</header>

				<Section id="ca-public-key" title="CA public key">
					<p>Hosts and SSH clients trust certificates signed by this key.</p>
					<pre class="key"><code>{publicKey}</code></pre>
					<p class="subtle">Fingerprint <code>{fingerprint}</code></p>
					<p><a href="/api/v4/ca">Download the CA public key</a></p>
				</Section>

				<Section id="request" title="Request a certificate">
					<p>
						Users and hosts request certificates with <a href={ClientRepositoryUrl}>ssh-ca-client</a>.
						Install it from its <a href={`${ClientRepositoryUrl}/releases`}>releases</a>, then ask your administrator for its settings.
					</p>
				</Section>

				<Section id="trust-users" title="Trust user certificates on a host">
					<p>Save the CA public key on the host:</p>
					<Snippet lines={[`curl -fsS ${origin}/api/v4/ca | sudo tee /etc/ssh/ca.pub`]} />
					<p>Then add the following to <code>sshd_config</code> (or a file in <code>/etc/ssh/sshd_config.d/</code>) and reload <code>sshd</code>:</p>
					<Snippet lines={[
						"PubkeyAuthentication yes",
						"TrustedUserCAKeys /etc/ssh/ca.pub",
						"AuthorizedPrincipalsFile /etc/ssh/principals.d/%u",
					]} />
					<p class="subtle">Each file in <code>/etc/ssh/principals.d/</code> is named after a local user and lists the certificate principals allowed to log in as that user, one per line.</p>
				</Section>

				<Section id="trust-hosts" title="Trust host certificates in SSH clients">
					<p>
						Add this line to <code>/etc/ssh/ssh_known_hosts</code> (for every user) or <code>~/.ssh/known_hosts</code> (for one user),
						replacing <code>*.example.com</code> with the host names whose certificates this CA signs:
					</p>
					<pre class="key"><code>{`@cert-authority *.example.com ${publicKey}`}</code></pre>
				</Section>

				<Section id="revocation" title="Refuse revoked certificates">
					<p>
						Revoked certificates are listed in signed key revocation lists (KRLs), one for user certificates
						at <code>{`${origin}/api/v4/user/krl`}</code> and one for host certificates at <code>{`${origin}/api/v4/host/krl`}</code>.
						ssh-ca-client downloads a KRL, checks its signature with the CA public key and writes it where OpenSSH can read it.
					</p>
					<h3>On a host, for sshd</h3>
					<Snippet lines={["sudo ssh-ca-client-cli krl --out /etc/ssh/revocation_list"]} />
					<p>Then add the following to <code>sshd_config</code> and reload <code>sshd</code>:</p>
					<Snippet lines={["RevokedKeys /etc/ssh/revocation_list"]} />
					<p class="subtle">Write the KRL before setting <code>RevokedKeys</code>, as <code>sshd</code> refuses all public key authentication when it cannot read the file.</p>
					<h3>On a client, for ssh</h3>
					<Snippet lines={["ssh-ca-client-cli krl --host --out ~/.ssh/revocation_list"]} />
					<p>Then add the following to <code>~/.ssh/config</code>:</p>
					<Snippet lines={["RevokedHostKeys ~/.ssh/revocation_list"]} />
					<p class="subtle">Refresh the KRLs regularly, as certificates can be revoked at any time.</p>
				</Section>

				<Section id="links" title="Links">
					<ul class="links">
						<li><a href="/docs">API documentation</a></li>
						<li><a href="/api/v4/ca">CA public key</a></li>
						<li><a href="/api/v4/user/krl">User KRL</a></li>
						<li><a href="/api/v4/host/krl">Host KRL</a></li>
						<li><a href={ClientRepositoryUrl}>ssh-ca-client</a></li>
						<li><a href={`${ClientRepositoryUrl}/releases`}>ssh-ca-client releases</a></li>
						{adminUrl !== undefined && <li><a href={adminUrl}>Admin UI</a></li>}
					</ul>
				</Section>

				<footer>serverless-ssh-ca</footer>
			</main>
		</body>
	</html>
)
