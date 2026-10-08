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

export type SSHExtension = {
    critical: boolean;
    name: string;
    data: Buffer<ArrayBuffer>
}

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
 * The bindings (environment) the CA expects, see {@link CaDatabase} and
 * {@link CaSecret} for the non-string bindings.
 */
export interface SshCaBindings {
    DB: CaDatabase
    DB_CERTIFICATE_RETENTION: string
    PRIVATE_KEY: CaSecret
    SSH_CERTIFICATE_EXTENSIONS: string
    SSH_CERTIFICATE_LIFETIME: string
    SSH_CERTIFICATE_INCLUDE_SELF?: string | boolean
    SSH_CERTIFICATE_INCLUDE_SELF_EMAIL?: string | boolean
    SSH_CERTIFICATE_PRINCIPALS?: string | string[]
    SSH_HOST_CERTIFICATE_LIFETIME: string
    SSH_HOST_CERTIFICATE_ALLOWED_EMAILS?: string | string[]
    SSH_HOST_CERTIFICATE_ALLOWED_ROLES?: string | string[]
    ISSUER_DN: string
	JWT_JWKS_URL: string
	JWT_AUD?: string | string[]
	JWT_ISSUER: string
	JWT_ALGORITHMS: string | string[]
	JWT_SSH_CERTIFICATE_PRINCIPALS_CLAIM: string
	CERTIFICATE_REQUEST_TIME_SKEW_MAX: string
	LOG_LEVEL?: string
}
