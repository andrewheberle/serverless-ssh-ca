import { exportJWK, generateKeyPair, SignJWT, type CryptoKey, type JWK, type JWTPayload } from "jose"
import { vi } from "vitest"

/**
 * An identity-aware proxy in front of the admin UI, which signs JWTs with
 * keys from a JWKS generated locally. Its JWKS URL is https, so it is served
 * by stubbing the global fetch rather than by the test IdP.
 */
export interface Proxy {
	jwksUrl: string
	issuer: string
	audience: string
	/** Signs a JWT, by default with the proxy's RS256 key, issued by the proxy for its audience and valid for five minutes */
	sign(claims: JWTPayload, options?: SignOptions): Promise<string>
	/** Serves the JWKS from the global fetch, passing every other request through */
	serveJwks(): void
}

export interface SignOptions {
	/** The key to sign with: the proxy's RS256 or ES256 key, or an RS256 key that is not in the JWKS but has the same key ID */
	key?: "rs256" | "es256" | "unknown"
	issuer?: string
	audience?: string
	/** When the JWT expires, in seconds since the epoch */
	expires?: number
}

type SigningKey = { alg: string, kid: string, privateKey: CryptoKey }

const publicJwk = async (publicKey: CryptoKey, alg: string, kid: string): Promise<JWK> => ({ ...(await exportJWK(publicKey)), alg, kid, use: "sig" })

/**
 * Creates an identity-aware proxy with its own keys and JWKS URL.
 *
 * @param name A name for the proxy, which makes its JWKS URL different from any other proxy's, so keys cached by jose for one are not used for another
 */
export const createProxy = async (name: string): Promise<Proxy> => {
	const issuer = `https://${name}.cloudflareaccess.com`
	const jwksUrl = `${issuer}/cdn-cgi/access/certs`
	const audience = `${name}-aud`

	const rsa = await generateKeyPair("RS256")
	const ec = await generateKeyPair("ES256")
	const other = await generateKeyPair("RS256")
	const keys: Record<NonNullable<SignOptions["key"]>, SigningKey> = {
		rs256: { alg: "RS256", kid: "rs256", privateKey: rsa.privateKey },
		es256: { alg: "ES256", kid: "es256", privateKey: ec.privateKey },
		unknown: { alg: "RS256", kid: "rs256", privateKey: other.privateKey },
	}
	const jwks = { keys: [await publicJwk(rsa.publicKey, "RS256", "rs256"), await publicJwk(ec.publicKey, "ES256", "es256")] }

	return {
		jwksUrl,
		issuer,
		audience,
		sign: async (claims, options = {}) => {
			const key = keys[options.key ?? "rs256"]
			return await new SignJWT(claims)
				.setProtectedHeader({ alg: key.alg, kid: key.kid })
				.setIssuer(options.issuer ?? issuer)
				.setAudience(options.audience ?? audience)
				.setIssuedAt()
				.setExpirationTime(options.expires ?? Math.floor(Date.now() / 1000) + 300)
				.sign(key.privateKey)
		},
		serveJwks: () => {
			const original = globalThis.fetch
			vi.spyOn(globalThis, "fetch").mockImplementation(async (input, init) => {
				const url = input instanceof Request ? input.url : input.toString()
				if (url === jwksUrl) {
					return Response.json(jwks)
				}

				return await original(input, init)
			})
		},
	}
}
