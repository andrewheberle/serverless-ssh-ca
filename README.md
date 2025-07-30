# Serverless SSH CA in Workers

This repository contains a serverless Certificate Authority that can be used
to provide signed certificates for SSH access running on Cloudflare Workers.

## Architecture

The solutions comprises of the CA running as a Worker, Go based client and 
an external OIDC IdP.

The IdP may be any OIDC compatible service that returns a JWT with at least
an `email` claim in the OIDC identity token, however at this time only
Cloudflare Access has been tested.

The flow to obtain a certificate is as follows:

1. The user initiates `ssh-ca-client login`
2. If required a new SSH key is generated and the a browser is opened to
   visit `http://localhost:3000/auth/login`
3. The client redirects the user to the configured IdP
4. The IdP returns the user to the callback URL (default
   `http://localhost:3000/auth/callback`)
5. The client uses the JWT from the IdP as `Authorization: Bearer <TOKEN>`
   in a `POST` request containing the users SSH public key to the CA's
   `/api/v1/certificate` endpoint
6. The CA verifies the incoming JWT and assuming it is valid and verified, will respond with a signed certificate based on the provided public key
7. The client saves the certificate and adds the SSH private key and certificate to the local SSH Agent.

## Deployment

Once you have cloned this repository, firstly install the dependencies:

```sh
npm install
```

1. After installation copy your own `wrangler` file:

```sh
cp wrangler.jsonc.example wrangler.jsonc
```

2. Edit the variables in `wrangler.jsonc`:

```jsonc
"vars": {
    // This is the issuer of your SSH certificates
    "ISSUER_DN": "CN=SSH CA,O=Internet Widgets Pty Ltd,C=US",
    // This is the URL for the CA to verify the JWT provided by the client
    "JWT_JWKS_URL": "https://example.com/.well-known/jwks.json",
    // The expected audience of the JWT
    "JWT_AUD": "<jwtaudience>",
    // The supported JWT algorithms
    "JWT_ALGORITHMS": ["RS256"],
    // The lifetime of the issued SSH certificates
    "SSH_CERTIFICATE_LIFETIME": "24 hours",
    // A list of principals to add to the certificate
    "SSH_CERTIFICATE_PRINCIPALS": ["ssh-admin"],
    // Whether to add the users own name as a valid principal
    "SSH_CERTIFICATE_INCLUDE_USER": false,
    // The list of SSH extensions to add to the certificate
    "SSH_CERTIFICATE_EXTENSIONS": [
        "permit-X11-forwarding",
        "permit-agent-forwarding",
        "permit-port-forwarding",
        "permit-pty",
        "permit-user-rc",
    ]
},
```

3. Add the secret for your SSH certificate authority private key:

```jsonc
"secrets_store_secrets": [
    {
        "binding": "PRIVATE_KEY",
        // The ID of the secret store
        "store_id": "<secret store id>",
        // Then name of the secret
        "secret_name": "<secret name>"
    }
]
```

The secret should be an OpenSSH private key generated as follows:

```sh
ssh-keygen -t ecdsa -b 256 -f path/to/ca_key
```

Other key types and sizes apart from ECDSA should work fine but are untested.

4. Generate the Worker types for your deployment:

```sh
npm run cf-typegen
```

5. Deploy your Worker:

```sh
npm run deploy
```

## Configuration

### Identity Provider

TODO: Add IdP config example here

The claims that are supported in the identity token are as follows:

```json
{
    "email": "user@example.com",
    "principals": [
        "list",
        "of",
        "additional",
        "principals"
    ]
}
```

The `email` claim is required and the `principals` claim is optional.

Any addtional `principals` in the identity token will be added as `principals`
to the issued certificate.

### Client

The client requires a configuration file that defines the details of the OIDC
IdP and where to find the SSH CA as follows:

```yaml
oidc:
  issuer: OIDC Issuer
  client_id: OIDC Client ID
  scopes: ["openid", "email", "profile"]
  access_type: offline
  redirect_url: http://localhost:3000/auth/callback
ssh:
  name: id_ssh_user
  ca_url: https://ca.example.com/api/v1/certificate
```

The client can be built as follows:

```sh
go install github.com/andrewheberle/severless-ssh-ca@latest
```

Assuming a local SSH agent is running, the client can be started as follows:

```sh
ssh-ca-client login
```

This should automatically start a web browser to initiate the OIDC login flow,
if not you may manually visit `http://localhost:3000/auth/login` to start this
process.

### SSH Endpoints

For systems to allow SSH login using certiifcates the following configuration
changes must be made:

```ssh
PubkeyAuthentication yes
TrustedUserCAKeys /etc/ssh/ca.pub
AuthorizedPrincipalsFile /etc/ssh/principals.d/%u
```

The contents of `/etc/ssh/ca.pub` is the public key of the SSH CA, which can
be retrieved as follows:

```sh
curl https://ca.example.com/api/v1/ca | sudo tee /etc/ssh/ca.pub
```

The `/etc/ssh/principals.d` directory should contain a file corresponding to
a local user that contains a list of principals that should be allowed
login.

Using the example principals in `SSH_CERTIFICATE_PRINCIPALS` above, the
following file named `/etc/ssh/principals.d/admin` would allow login
as the user `admin` for the bearer of an issued (and valid) certificate:

```
ssh-admin
```