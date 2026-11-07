import { sha256 } from "@noble/hashes/sha2.js"
import { bytesToHex } from "@noble/hashes/utils.js"
import type { Context } from "hono"

/** The number of hex characters of an asset's SHA-256 put in its name */
export const AssetHashLength = 8

// the content type each kind of asset is served with
const ContentTypes = {
	css: "text/css; charset=utf-8",
	js: "text/javascript; charset=utf-8",
} as const

/** The kinds of file served as a {@link HashedAsset} */
export type AssetExtension = keyof typeof ContentTypes

/**
 * Who may keep a copy of a {@link HashedAsset}: only the browser
 * (`private`), for assets behind a sign-in, or shared caches such as a CDN
 * too (`public`).
 */
export type AssetCaching = "private" | "public"

/**
 * A stylesheet or script served under a name that includes a hash of its
 * content, such as `/admin/style-1a2b3c4d.css`, so the name changes
 * whenever the content does. Browsers can then keep it for as long as they
 * like, and a page that links a new version is never given an old copy.
 */
export type HashedAsset = {
	/** The path it is served at, `<base path>/<name>-<hash>.<extension>` */
	readonly path: string
	/** The exact text served, which the hash in the path is of */
	readonly content: string
	/** The `Content-Type` it is served with */
	readonly contentType: string
}

/**
 * Returns the hash of an asset's content put in its name: the first
 * {@link AssetHashLength} hex characters of the SHA-256 of its UTF-8 bytes.
 *
 * @param content The exact text served
 * @returns The hash, such as `1a2b3c4d`
 */
export const assetHash = (content: string): string =>
	bytesToHex(sha256(new TextEncoder().encode(content))).slice(0, AssetHashLength)

/**
 * Names an asset after a hash of its content, see {@link HashedAsset}.
 *
 * @param basePath The path it is served under, without a trailing slash,
 * such as `/admin`, or `""` for the root
 * @param name The name before the hash, such as `style`
 * @param extension The kind of file, which decides its content type
 * @param content The exact text served
 * @returns The asset
 */
export const hashedAsset = (basePath: string, name: string, extension: AssetExtension, content: string): HashedAsset => ({
	path: `${basePath}/${name}-${assetHash(content)}.${extension}`,
	content,
	contentType: ContentTypes[extension],
})

/**
 * Returns the `Cache-Control` a {@link HashedAsset} is served with, which
 * lets it be kept for a year without being checked again, as its name
 * changes whenever its content does.
 *
 * @param caching Who may keep a copy
 * @returns The header value
 */
export const assetCacheControl = (caching: AssetCaching): string => `${caching}, max-age=31536000, immutable`

/**
 * Responds with a {@link HashedAsset}, with its content type and the
 * `Cache-Control` from {@link assetCacheControl}, which the security headers
 * middleware leaves in place.
 *
 * @param c The context of the request
 * @param asset The asset
 * @param caching Who may keep a copy
 * @returns The response
 */
export const assetResponse = (c: Context, asset: HashedAsset, caching: AssetCaching): Response =>
	c.body(asset.content, 200, {
		"Content-Type": asset.contentType,
		"Cache-Control": assetCacheControl(caching),
	})
