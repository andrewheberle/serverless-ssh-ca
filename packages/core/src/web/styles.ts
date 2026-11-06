/**
 * The styles shared by every HTML page the CA serves (the admin UI and the
 * landing page): the colour tokens, type, links, code and cards. Each page
 * adds its own layout rules after these and serves the result from its own
 * path, so the CSP can allow styles from `'self'` only.
 *
 * The pages should also look like siblings of the page ssh-ca-client shows at
 * the end of its login flow (`internal/pkg/auth/templates/result.html` in
 * https://github.com/andrewheberle/ssh-ca-client), as the same people see
 * both. That page is not built from these styles, so when either side
 * changes its look, keep the other in step: a neutral canvas with cards,
 * system sans and monospace faces, green for success and red for errors, and
 * a round tinted badge holding an inline SVG icon.
 */
export const BaseStylesheet = `/*
 * The colours, spacing and component shapes follow Cloudflare's Kumo design
 * system (https://github.com/cloudflare/kumo), written as plain CSS so the
 * pages need no build step, dependency or client-side JavaScript.
 * The colour values are from Kumo's theme, used under the MIT License:
 * Copyright (c) 2026 Cloudflare, Inc.
 */
:root {
	color-scheme: light dark;
	--canvas: light-dark(oklch(98.75% 0 0), oklch(10% 0 0));
	--base: light-dark(#fff, oklch(17% 0 0));
	--elevated: light-dark(oklch(98% 0 0), oklch(12% 0 0));
	--tint: light-dark(oklch(97% 0 0), oklch(26.9% 0 0));
	--recessed: light-dark(oklch(96% 0 0), oklch(15% 0 0));
	--control: light-dark(#fff, oklch(21% 0.006 285.885));
	--line: light-dark(oklch(14.5% 0 0 / 0.1), oklch(32% 0 0));
	--hairline: light-dark(oklch(93.5% 0 0), oklch(26.9% 0 0));
	--fill: light-dark(oklch(92.2% 0 0), oklch(26.9% 0 0));
	--focus: light-dark(oklch(15% 0 0 / 0.5), oklch(93.5% 0 0 / 0.5));
	--brand: light-dark(oklch(0.5772 0.2324 260), oklch(0.52 0.2324 260));
	--text: light-dark(oklch(21% 0.006 285.885), oklch(97% 0 0));
	--text-strong: light-dark(oklch(14.5% 0 0), oklch(98.5% 0 0));
	--text-subtle: light-dark(oklch(55.6% 0 0), oklch(70.8% 0 0));
	--link: light-dark(oklch(42.4% 0.199 265.638), oklch(70.7% 0.165 254.624));
	--success: light-dark(oklch(43.2% 0.095 166.913), oklch(90.5% 0.093 164.15));
	--success-tint: light-dark(oklch(96.2% 0.043 156.7 / 0.57), oklch(39.3% 0.096 152.3 / 0.2));
	--danger: light-dark(oklch(50.5% 0.213 27.518), oklch(70.4% 0.191 22.216));
	--danger-tint: light-dark(oklch(93.6% 0.032 17.7 / 0.42), oklch(42.9% 0.176 28.7 / 0.17));
	--neutral: light-dark(oklch(26.9% 0 0), oklch(92.2% 0 0));
	--mono: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
	font-family: system-ui, -apple-system, "Segoe UI", sans-serif;
	font-size: 15px;
	line-height: 1.5;
}

*, *::before, *::after {
	box-sizing: border-box;
}

body {
	background: var(--canvas);
	color: var(--text);
	margin: 0;
}

a {
	color: var(--link);
	text-decoration: none;
}

a:hover {
	text-decoration: underline;
}

:focus-visible {
	outline: 2px solid var(--brand);
	outline-offset: 2px;
}

code, .mono {
	font-family: var(--mono);
	font-size: 0.9375em;
	overflow-wrap: anywhere;
}

h2 {
	color: var(--text-strong);
	font-size: 1.25rem;
	font-weight: 600;
	margin: 0;
}

.card {
	background: var(--base);
	border-radius: 0.5rem;
	box-shadow: 0 0 0 1px var(--line);
	padding: 1rem;
}
`
