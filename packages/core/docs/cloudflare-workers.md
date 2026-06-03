# Cloudflare Workers

After deployment on Workers using the
[template](https://github.com/andrewheberle/serverless-ssh-client-template)
repository configuration is handled by mking changes in your `wrangler.jsonc`
file.

## Configuration

The following configuration options are available via variables set in
`wrangler.jsonc`:

```jsonc
{
	"$schema": "node_modules/wrangler/config-schema.json",
    /** additional Wrangler config **/
    "vars": {
        // This is the issuer of your SSH certificates
        "ISSUER_DN": "CN=SSH CA,O=Internet Widgets Pty Ltd,C=US",
        // This is the URL for the CA to verify the JWT provided by the client
        "JWT_JWKS_URL": "https://example.com/.well-known/jwks.json",
        // The issuer of the JWT access token
        "JWT_ISSUER": "https://example.com/",
        // The supported JWT algorithms as a comma seperated list
        "JWT_ALGORITHMS": "RS256",
        // An OIDC claim included in the users identity token that will be used to
        // populate the list of principals on the issued certificate
        "JWT_SSH_CERTIFICATE_PRINCIPALS_CLAIM": "groups",
        // The lifetime of the issued SSH certificates
        "SSH_CERTIFICATE_LIFETIME": "24 hours",
        // A comma seperated list of additional principals to add to all issued user certificates
        "SSH_CERTIFICATE_PRINCIPALS": "",
        // Whether to add the users own name as a valid principal
        "SSH_CERTIFICATE_INCLUDE_SELF": "false",
        // The list of SSH extensions to add to the certificate as a comma seperated list
        "SSH_CERTIFICATE_EXTENSIONS": "permit-X11-forwarding,permit-agent-forwarding,permit-port-forwarding,permit-pty,permit-user-rc",
        // A comma seperated list of users who are permitted to request SSH host certificates based on the email claim from the OIDC IdP
        "SSH_HOST_CERTIFICATE_ALLOWED_EMAILS": "",
        // A comma seperated list of roles that are permitted to request SSH host certificates based on the claim specified in JWT_SSH_CERTIFICATE_PRINCIPALS_CLAIM
        "SSH_HOST_CERTIFICATE_ALLOWED_ROLES": "",
        // The lifetime of issued Host SSH certificates in human readable form (ie "45 days"), although the client may request a shorter duration
        "SSH_HOST_CERTIFICATE_LIFETIME": "30 days",
        // The maximum time skew allowed for certificate requests
        "CERTIFICATE_REQUEST_TIME_SKEW_MAX": "90 seconds",
        // Set this to "debug" to enable more logging
        "LOG_LEVEL": "info"
    },
}
```
