# Upgrading to 1.0

serverless-ssh-ca 1.0.0 removes API v3 and tightens what the CA accepts, in
its configuration and in requests. This page covers what to check before you
upgrade from any 0.x release. The changelog lists every change.

## What 1.0.0 promises

From 1.0.0, a breaking change to any of the following needs a new major
version:

- The `/api/v4` HTTP API, as described by
  [`openapi.json`](../packages/core/openapi.json). This includes:
  - the v4 proof of possession wire format: the `Proof-Of-Possession` header,
    `timestamp.fingerprint.signature`, and the
    `request-proof-of-possession@…` namespace
  - the KRL signature: an armored SSHSIG over the KRL in the
    `krl@com.github.serverless-ssh-ca.andrewheberle` namespace

  The path stays `/api/v4`, as the API version is separate from the package
  version.
- The exports of `@andrewheberle/serverless-ssh-ca`.
- The configuration: environment variables and bindings.
- Upgrades. Upgrading from any earlier release migrates the database
  automatically the first time it is used.
- `@andrewheberle/serverless-ssh-ca-testing`, which is versioned with the CA.
  Its command line, configuration file and log format stay compatible, so
  clients' end-to-end tests keep working.

The database schema is not covered. It is internal to the CA and can change
in any release, and running an older release against a database a newer one
has migrated is not supported (see
[Database](../packages/core/README.md#database)).

## Before you upgrade

1. **Back up the database.** 1.0.0 migrates it the first time it is used, and
   an earlier release cannot use it afterwards, so a rollback means restoring
   the backup along with the earlier release. On Cloudflare, note a
   [D1 Time Travel](https://developers.cloudflare.com/d1/reference/time-travel/)
   restore point. On Node.js, copy the SQLite file.
2. **Upgrade clients.** Every client must be ssh-ca-client 0.24.0 or later
   (see [API v3 is removed](#api-v3-is-removed)).
3. **Check the configuration** against the
   [Validation](../packages/core/README.md#validation) table. A configuration
   that 0.x accepted can be refused by 1.0.0 (see
   [Configuration](#configuration)).
4. **Check who may request host certificates.** Two settings now match more
   requesters than before (see [Host certificate allowlists](#host-certificate-allowlists)).

## API v3 is removed

A v3 proof of possession signed only a timestamp and the key fingerprint, in
one namespace shared by every endpoint. A proof captured from one v3 request
could be replayed against any other v3 endpoint while it was valid
([ADR 0006](adr/0006-proofs-of-possession-are-bound-to-the-request.md)). v4
binds each proof to its request.

Every request under `/api/v3` now gets `410 Gone`, with a message saying to
upgrade ssh-ca-client. ssh-ca-client has used only v4 since 0.24.0, so any
client from 0.24.0 on is not affected. Upgrade older clients before the CA:
once the CA is on 1.0.0 they can no longer get or renew certificates.

## Requests the v4 API now refuses

Requests from ssh-ca-client are not affected by these changes. If you call
the API from your own code, check that it:

- sends two different tokens. A request whose access token (in
  `Authorization`) is the same string as its identity token is refused with
  `400`, as without `JWT_ACCESS_TOKEN_AUD` an identity token would otherwise
  pass as both. Identity providers never issue the same string as both
  tokens.
- writes the proof of possession's timestamp as digits only, with no sign,
  leading zero, decimal point or other text, and at most 16 digits.
- encodes the proof's signature in standard base64 with padding, not
  URL-safe or unpadded base64.

The `Bearer` scheme of the `Authorization` header is now accepted in any
case, such as `bearer`.

`openapi.json` no longer lists status codes that some operations never
returned, so a client generated from it may have fewer error types. The
codes the API returns are the same.

## Configuration

The configuration is now validated with the same rules on Cloudflare Workers
and Node.js. A configuration that was accepted before is refused when:

- `JWT_AUD` is unset or empty. Before, a Worker without it served the CA key
  and KRLs but failed every certificate request. Set it to the audience of
  your identity tokens, usually the OIDC client ID.
- `JWT_JWKS_URL` or `OIDC_USERINFO_URL` is an `http` URL for any host but the
  local machine. Use `https`.
- any list setting has an empty entry, such as `"a,,b"` or a trailing comma.
  Entries are trimmed, so `"a, b"` is still accepted.
- `JWT_ALGORITHMS` has an entry that is not an asymmetric algorithm, such as
  `HS256` or `none`.
- an entry of `SSH_CERTIFICATE_EXTENSIONS` has whitespace in it.
- `SSH_CERTIFICATE_LIFETIME` is under 5 minutes, or
  `SSH_HOST_CERTIFICATE_LIFETIME` is under 24 hours, or either is not a whole
  number of seconds.
- `CERTIFICATE_REQUEST_TIME_SKEW_MAX` is zero or over 5 minutes.

How a refused configuration is reported depends on the runtime. On Cloudflare
Workers the problems are logged once, at error level, and every request gets
a `500` until the configuration is fixed, so check
`https://<your CA>/api/v4/ca` and the Worker's logs after deploying. On
Node.js, `createSshCa` and `bindingsFromEnv` throw an
`InvalidConfigurationError` listing every problem.

On Node.js, `bindingsFromEnv` now treats an empty `OIDC_USERINFO_URL` as
unset, and an unset `SSH_CERTIFICATE_EXTENSIONS` as no extensions, as Workers
always has.

No settings or bindings were added or renamed.

### Host certificate allowlists

Two settings now let in requesters that 0.x refused:

- `SSH_HOST_CERTIFICATE_ALLOWED_EMAILS` is compared without regard to case,
  so `Admin@Example.com` now matches `admin@example.com`.
- `SSH_HOST_CERTIFICATE_ALLOWED_ROLES` entries now have spaces replaced with
  underscores, as roles from the `JWT_SSH_CERTIFICATE_PRINCIPALS_CLAIM` claim
  always had. A role configured as `Host Admins` never matched before, and now
  matches the group `Host Admins`.

Check that everyone these settings now match should be able to request host
certificates.

## Running on Node.js

`EnvSchema` and the `CaEnv` type are no longer exported from
`@andrewheberle/serverless-ssh-ca/node`. Use `bindingsFromEnv`, which
validates the environment with the same rules as `createSshCa`.

Node.js 24 LTS is the supported version (see
[Supported Platforms](../README.md#supported-platforms)).

If the admin UI runs on Node.js behind a proxy that terminates TLS, set
`ADMIN_HOSTNAME` (see [Admin UI](../packages/core/README.md#admin-ui)). This
was already needed for revocations to work, and a request refused for this
reason is now logged at warning level.

## The database

1.0.0 adds no migrations. Upgrading from 0.28.0 or earlier runs migration
`0005_renewal_of`, which now takes time in proportion to the number of host
certificates rather than its square, so large databases can upgrade within
D1's query time limit.

## Deploy to Cloudflare deployments

The Deploy to Cloudflare button now deploys from [`template/`](../template)
in this repository, and the separate `serverless-ssh-ca-template` repository
is archived. A deployment made with the button has its own copy of the
template, so it keeps working, but nothing updates it. To upgrade one:

1. In its `package.json`, change the `@andrewheberle/serverless-ssh-ca`
   version to `1.0.0`. A range such as `^0.23.0` never reaches 1.0.0.
2. In its `wrangler.jsonc`, set `JWT_AUD`, which the old template left empty,
   and check the other settings against [Configuration](#configuration).
3. Commit, and Workers Builds deploys the upgrade.
