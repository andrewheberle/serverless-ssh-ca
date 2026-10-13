const oidcBase = `http://localhost:${process.env.OIDC_PORT ?? "4567"}`

export type TokenClaims = {
    sub: string
    email: string
    [key: string]: unknown
}

export const getAccessToken = async (claims: TokenClaims): Promise<string> => {
    const res = await fetch(`${oidcBase}/token`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ claims }),
    })
    const { token } = await res.json() as { token: string }
    return `Bearer ${token}`
}

export const getIdentityToken = async (claims: TokenClaims): Promise<string> => {
    const res = await fetch(`${oidcBase}/token`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ claims }),
    })
    const { token } = await res.json() as { token: string }
    return token
}

/**
 * Returns an opaque (not a JWT) access token as an Authorization header,
 * which the test IdP's userinfo endpoint responds to with the given claims,
 * or with the given status and raw body.
 */
export const getOpaqueAccessToken = async (userinfo: { claims: Record<string, unknown> } | { status: number, raw: string }): Promise<string> => {
    const res = await fetch(`${oidcBase}/opaque-token`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(userinfo),
    })
    const { token } = await res.json() as { token: string }
    return `Bearer ${token}`
}
