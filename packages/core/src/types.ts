import { JWTPayload } from "jose"

// this is the JSON payload of a certificate request
export type CertificateSignerPayload = {
    public_key: string
    identity: string
    extensions?: string[]
	lifetime?: number
    nonce?: string
}

export type CertificateSignerResponse = {
    certificate: string
}

// this is the expected JWT payload for a certificate request
export type CertificateRequestJWTPayload = {
    email: string
    sub: string
    [key: string]: string | string[]
} & JWTPayload

/**
 * The result of executing a statement via {@link CaPreparedStatement.run} or
 * {@link CaDatabase.batch}, modelled on a Cloudflare D1 result.
 */
export interface CaDatabaseResult {
    /** Whether the statement executed successfully */
    success: boolean
    meta?: {
        /** The number of rows changed by the statement */
        changes?: number
        /** The rowid of the last row inserted */
        last_row_id?: number
        /** How long the statement took to execute in milliseconds */
        duration?: number
    }
}

/**
 * The result of executing a statement that returns rows via
 * {@link CaPreparedStatement.all}.
 */
export interface CaDatabaseQueryResult extends CaDatabaseResult {
    /** The rows returned, one object per row keyed by column name */
    results: unknown[]
}

/**
 * The subset of a Cloudflare D1 prepared statement used by the CA.
 */
export interface CaPreparedStatement {
    /** Bind positional (`?`) parameters, returning a statement to execute */
    bind(...values: unknown[]): CaPreparedStatement
    /** Execute the statement and return all rows */
    all(): Promise<CaDatabaseQueryResult>
    /** Execute the statement without returning rows */
    run(): Promise<CaDatabaseResult>
}

/**
 * The subset of a Cloudflare D1 database binding used by the CA.
 *
 * A Workers `D1Database` binding satisfies this structurally, so the package
 * does not need to depend on `@cloudflare/workers-types`. Any other SQLite
 * compatible database may be used by implementing this interface.
 *
 * The SQL the CA runs is SQLite dialect, and statements passed to
 * {@link CaDatabase.prepare} may contain more than one SQL statement.
 * Schema migrations rely on {@link CaDatabase.batch} being atomic so they can
 * be applied safely by concurrent requests.
 */
export interface CaDatabase {
    /** Prepare a SQL query for execution, see {@link CaPreparedStatement} */
    prepare(query: string): CaPreparedStatement
    /** Execute several prepared statements atomically, returning a result for each */
    batch(statements: CaPreparedStatement[]): Promise<CaDatabaseResult[]>
    /** Execute one or more SQL statements without parameters */
    exec(query: string): Promise<unknown>
}

/**
 * The subset of a Cloudflare Secrets Store binding used to load the CA private key.
 *
 * A Workers `SecretsStoreSecret` binding satisfies this structurally.
 */
export interface CaSecret {
    get(): Promise<string>
}

/**
 * A rate limiter, with the same shape as a Cloudflare Workers rate limit
 * binding.
 *
 * A Workers `RateLimit` binding satisfies this structurally. On other
 * runtimes any limiter with the same shape may be used.
 */
export interface CaRateLimiter {
    /**
     * Counts a request against the limit for a key
     *
     * @param options The key the request is counted against, for example the client IP address
     * @returns Whether the request is within the limit
     */
    limit(options: { key: string }): Promise<{ success: boolean }>
}

/**
 * A key-value cache, with the subset of a Cloudflare Workers KV namespace
 * binding used by the CA.
 *
 * A Workers `KVNamespace` binding satisfies this structurally. On other
 * runtimes any cache with the same shape may be used, such as the in-memory
 * cache returned by `cacheInMemory` from `@andrewheberle/serverless-ssh-ca/node`.
 */
export interface CaCache {
    /** Returns the value for a key, or null if there is none */
    get(key: string): Promise<string | null>
    /** Sets the value for a key, which may expire after `expirationTtl` seconds */
    put(key: string, value: string, options?: { expirationTtl?: number }): Promise<void>
}

/**
 * The bindings (environment) the CA expects, see {@link CaDatabase},
 * {@link CaSecret}, {@link CaRateLimiter} and {@link CaCache} for the non-string
 * bindings.
 */
export interface SshCaBindings {
	CERTIFICATE_REQUEST_TIME_SKEW_MAX: string
	JWT_ALGORITHMS: string | string[]
	/** The audience the identity token, and unless {@link SshCaBindings.JWT_ACCESS_TOKEN_AUD} is set the access token, must be issued for */
	JWT_AUD: string | string[]
	/** The audience the access token must be issued for, when it differs from {@link SshCaBindings.JWT_AUD} */
	JWT_ACCESS_TOKEN_AUD?: string | string[]
	/**
	 * The URL of the IdP's OIDC userinfo endpoint. When set, access tokens are
	 * verified by sending them to this endpoint instead of as JWTs, so IdPs
	 * that issue opaque access tokens can be used. The access token's audience
	 * is not checked, so {@link SshCaBindings.JWT_ACCESS_TOKEN_AUD} is not used.
	 */
	OIDC_USERINFO_URL?: string
	JWT_ISSUER: string
	JWT_JWKS_URL: string
	JWT_SSH_CERTIFICATE_PRINCIPALS_CLAIM: string
	LOG_LEVEL?: string
    DB_CERTIFICATE_RETENTION: string
    DB: CaDatabase
    ISSUER_DN: string
    PRIVATE_KEY: CaSecret
    /**
     * Limits requests to issue, renew and revoke certificates, see
     * {@link CaRateLimiter}. Requests are not limited when this is not set.
     */
    RATE_LIMITER?: CaRateLimiter
    /**
     * Caches KRLs until a certificate is revoked, see {@link CaCache}. KRLs
     * are generated for every request when this is not set.
     */
    CACHE?: CaCache
    /** The extensions included in user certificates by default, and the only ones a requester may ask for; none when not set */
    SSH_CERTIFICATE_EXTENSIONS?: string | string[]
    SSH_CERTIFICATE_INCLUDE_SELF_EMAIL?: string | boolean
    SSH_CERTIFICATE_INCLUDE_SELF?: string | boolean
    SSH_CERTIFICATE_LIFETIME: string
    SSH_CERTIFICATE_PRINCIPALS?: string | string[]
    SSH_HOST_CERTIFICATE_ALLOWED_EMAILS?: string | string[]
    SSH_HOST_CERTIFICATE_ALLOWED_ROLES?: string | string[]
    SSH_HOST_CERTIFICATE_LIFETIME: string
    /**
     * Whether to serve the landing page at `/`, which shows the CA public key,
     * generic setup instructions for hosts and clients, and links to the API
     * docs, the KRLs and (when it is turned on) the admin UI. `/` answers with
     * 404 when this is not set or is false.
     */
    LANDING_PAGE?: string | boolean
    /**
     * The request header an identity-aware proxy in front of `/admin` sends
     * its signed JWT in, for example `Cf-Access-Jwt-Assertion`. The admin UI
     * is turned off unless this, {@link SshCaBindings.ADMIN_JWKS_URL},
     * {@link SshCaBindings.ADMIN_JWT_ISSUER}, {@link SshCaBindings.ADMIN_JWT_AUD}
     * and an allowlist ({@link SshCaBindings.ADMIN_ALLOWED_EMAILS}, or
     * {@link SshCaBindings.ADMIN_ALLOWED_ROLES} with
     * {@link SshCaBindings.ADMIN_JWT_ROLES_CLAIM}) are all set.
     */
    ADMIN_JWT_HEADER?: string
    /** The https URL of the JWKS the proxy's JWTs are signed with */
    ADMIN_JWKS_URL?: string
    /** The issuer (`iss`) the proxy's JWT must have */
    ADMIN_JWT_ISSUER?: string
    /** The audiences (`aud`) the proxy's JWT may be issued for, at least one */
    ADMIN_JWT_AUD?: string | string[]
    /** The algorithms the proxy's JWT may be signed with, `RS256` when not set */
    ADMIN_JWT_ALGORITHMS?: string | string[]
    /** The emails of admins, compared case-insensitively with the `email` claim of the proxy's JWT */
    ADMIN_ALLOWED_EMAILS?: string | string[]
    /** The roles that make someone an admin, compared exactly with the values of {@link SshCaBindings.ADMIN_JWT_ROLES_CLAIM} */
    ADMIN_ALLOWED_ROLES?: string | string[]
    /** The claim of the proxy's JWT that holds the requester's roles, as a string or an array of strings */
    ADMIN_JWT_ROLES_CLAIM?: string
    /** The only host name the admin UI answers on, when set; requests to `/admin` on any other host name get 404 */
    ADMIN_HOSTNAME?: string
}
