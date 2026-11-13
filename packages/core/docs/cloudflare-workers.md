# Cloudflare Workers

After deployment on Workers using the
[template](https://github.com/andrewheberle/serverless-ssh-ca/tree/main/template)
repository configuration is handled by making changes in your `wrangler.jsonc`
file.

## Configuration

The following configuration options are available via variables set in
`wrangler.jsonc`:

```jsonc
{
	"$schema": "node_modules/wrangler/config-schema.json",
    /** additional Wrangler config **/
    "vars": {
        // The comment on the CA public key served at /api/v4/ca; it is not used in certificates
        "ISSUER_DN": "CN=SSH CA,O=Internet Widgets Pty Ltd,C=US",
        // The URL of the IdP's JWKS, which must be https (or http for localhost)
        "JWT_JWKS_URL": "https://example.com/.well-known/jwks.json",
        // The issuer (iss) of the access token and identity token
        "JWT_ISSUER": "https://example.com/",
        // The audience the identity token (and, unless JWT_ACCESS_TOKEN_AUD is set, the access token) must be issued for, such as the OIDC client ID. Required
        "JWT_AUD": "<client id>",
        // The supported JWT algorithms as a comma separated list
        "JWT_ALGORITHMS": "RS256",
        // An OIDC claim included in the users identity token that will be used to
        // populate the list of principals on the issued certificate
        "JWT_SSH_CERTIFICATE_PRINCIPALS_CLAIM": "groups",
        // The longest lifetime of user certificates (at least 5 minutes); a requester may ask for less
        "SSH_CERTIFICATE_LIFETIME": "24 hours",
        // A comma separated list of additional principals to add to all issued user certificates
        "SSH_CERTIFICATE_PRINCIPALS": "",
        // Whether to add the local part of the requester's email address (before the @) as a principal of user certificates
        "SSH_CERTIFICATE_INCLUDE_SELF": "false",
        // The extensions user certificates get by default, and the only ones a requester may ask for, as a comma separated list
        "SSH_CERTIFICATE_EXTENSIONS": "permit-X11-forwarding,permit-agent-forwarding,permit-port-forwarding,permit-pty,permit-user-rc",
        // A comma separated list of users who are permitted to request SSH host certificates based on the email claim from the OIDC IdP
        "SSH_HOST_CERTIFICATE_ALLOWED_EMAILS": "",
        // A comma separated list of roles that are permitted to request SSH host certificates based on the claim specified in JWT_SSH_CERTIFICATE_PRINCIPALS_CLAIM
        "SSH_HOST_CERTIFICATE_ALLOWED_ROLES": "",
        // The longest lifetime of host certificates (at least 24 hours), although the client may request a shorter duration
        "SSH_HOST_CERTIFICATE_LIFETIME": "30 days",
        // How far a proof of possession's timestamp may be from the CA's clock, at most 5 minutes
        "CERTIFICATE_REQUEST_TIME_SKEW_MAX": "90 seconds",
        // How long certificates are kept after they expire, or "infinite". Required
        "DB_CERTIFICATE_RETENTION": "1 year",
        // Set this to "debug" to enable more logging
        "LOG_LEVEL": "info"
    },
}
```
