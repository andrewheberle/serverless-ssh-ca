import type { FC, PropsWithChildren } from "hono/jsx"

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
	border-bottom: 1px solid currentColor;
	margin-bottom: 1rem;
}

h1 {
	font-size: 1.25rem;
	margin: 0 0 0.5rem;
}
`

/**
 * The page every admin UI page is rendered in. Values are escaped by JSX, so
 * nothing passed to it is ever treated as HTML.
 */
export const Layout: FC<PropsWithChildren<{ title: string }>> = ({ title, children }) => (
	<html lang="en">
		<head>
			<meta charset="utf-8" />
			<meta name="viewport" content="width=device-width, initial-scale=1" />
			<title>{title}</title>
			<link rel="stylesheet" href={StylesheetPath} />
		</head>
		<body>
			<header>
				<h1>SSH CA admin</h1>
			</header>
			<main>{children}</main>
		</body>
	</html>
)

/**
 * The admin UI's home page, which shows who the identity-aware proxy says is
 * signed in.
 */
export const SignedInPage: FC<{ email: string }> = ({ email }) => (
	<Layout title="SSH CA admin">
		<p>Signed in as {email}</p>
	</Layout>
)
