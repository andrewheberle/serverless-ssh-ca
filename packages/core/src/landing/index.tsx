import { Hono } from "hono"
import { html } from "hono/html"
import { AdminBasePath } from "../admin/index.js"
import { caConfig, type AdminConfig } from "../config.js"
import type { SshCaBindings } from "../types.js"
import { getPublic } from "../utils.js"
import { assetResponse } from "../web/assets.js"
import { securityHeaders } from "../web/headers.js"
import { LandingPage, LandingStylesheetAsset, LandingStylesheetPath } from "./pages.js"

/** The path the landing page is served at */
export const LandingPath = "/"

type LandingEnv = {
	Bindings: SshCaBindings
}

/**
 * Returns the link to the admin UI shown on the landing page, which is only
 * shown while the admin UI is turned on. When the admin UI is limited to one
 * host name the link is to that host name, as the landing page may be served
 * on another.
 *
 * @param admin The settings of the admin UI
 * @returns The link, or undefined when the admin UI is turned off
 */
export const adminLink = (admin: AdminConfig): string | undefined => {
	switch (admin.kind) {
		case "disabled":
		case "partial":
			return undefined
		case "enabled":
			return admin.hostname === undefined ? AdminBasePath : `https://${admin.hostname}${AdminBasePath}`
		default: {
			const unknown: never = admin
			throw new Error(`unknown admin configuration ${JSON.stringify(unknown)}`)
		}
	}
}

/**
 * Creates the landing page, a plain Hono app (not registered with chanfana,
 * so it is not part of the OpenAPI schema) to be mounted at the root of the
 * CA.
 *
 * It only has routes while `LANDING_PAGE` is set, and then only for
 * {@link LandingPath} and {@link LandingStylesheetPath}, so mounting it at the
 * root never answers for any other path. The stylesheet is only served at
 * its current hashed path, and may be cached by anyone, as the landing page
 * is public. While it is turned off those paths answer with 404, as they do
 * without it.
 *
 * @param env The bindings of the CA, whose configuration must be valid
 * @returns The landing page
 */
export const createLandingApp = (env: SshCaBindings): Hono<LandingEnv> => {
	const app = new Hono<LandingEnv>()
	const config = caConfig(env)
	if (!config.landingPage) {
		return app
	}

	app.get(LandingPath, securityHeaders<LandingEnv>(), async (c) => {
		const publicKey = await getPublic(c.env)

		return c.html(html`<!DOCTYPE html>${<LandingPage
			origin={new URL(c.req.url).origin}
			publicKey={publicKey.toString()}
			fingerprint={publicKey.fingerprint()}
			adminUrl={adminLink(config.admin)}
		/>}`)
	})

	app.get(LandingStylesheetPath, securityHeaders<LandingEnv>(), (c) => assetResponse(c, LandingStylesheetAsset, "public"))

	return app
}
