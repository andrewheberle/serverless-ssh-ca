## Name

ssh-ca-client-cli-login - Request and renew user SSH certificates from the Serverless SSH CA

## Synopsis

```sh
ssh-ca-client-cli [global options] login ] [--add]
                                           [--addr <address>]
                                           [--force]
                                           [--life <duration>]
                                           [--skip-agent]
                       
```

## Description

Issues or renews a users SSH certificates using an interactive OIDC
authentication flow for requests with the principals added to the certificate
based on the claims returned from the OIDC IdP.

Renewals may use a refresh token from the OIDC IdP if the configuration of the
IdP allows this.

## Global Options

See [Options](ssh-ca-client-cli.md#options)

## Options

`--add`
If an existing certificate exists, attempt to add this certificate to the local
SSH Agent on startup.

`--addr <address>`
The local listen address for the OIDC authentication process.

The default is `localhost:3000`.

`--force`
Force renewal of existing certificate(s) regardless of the current validity
period left.

`--life <duration>`
Request or renew a certificate with the sepecified duration.

The accepted minimum and maximum duration is enforced by the CA and for
renewals the duration may not be larger than the current certificate.

This is a `duration` so may be provided with the following units:

* `ms` - milliseconds
* `s` - seconds
* `h` - hours

The default is `24h`

`--life <duration>`
Request or renew a certificate with the sepecified duration.

The accepted minimum and maximum duration is enforced by the CA and for
renewals the duration may not be larger than the current certificate.

The default is `720h` (30 days)

`--skip-agent`
By default any issued certificate will be added to the local SSH Agent.

Passing `--skip-agent` disables this.

## Examples

* Request/renew a certificate:

  ```sh
  ssh-ca-client-cli login
  ```

* Force renewal of an existing certificate:

  ```sh
  ssh-ca-client-cli login --force
  ```

* Request a certificate with a shorter than default validity period:

  ```sh
  ssh-ca-client-cli login --life 1h
  ```

## Configuration

The following configuration options, specified by the `--config` flag, must be set.

The only optional value is `trusted_ca` however this it is strongly recommended to set this value.

```yaml
# The issuer, client_id, scopes and redirect_url must match your OIDC IdP
issuer: https://idp.example.com/
client_id: OIDC Client ID
scopes: ["openid", "email", "profile", "offline_access"]
redirect_url: http://localhost:3000/auth/callback
# The CA URL must match the route the Worker CA is deployed to
ca_url: https://ca.example.com/
# Providing the SSH public key of the CA is optional but recommended to allow the client to validate issued certificates are from the expected CA
trusted_ca: ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBMgJTsYW+tHl0lz/rnO8djbwq0B3uZ5sGugXU6Ha5S2rTdzMDgit2DO+hoivdT4I07rMrRtmFI179wUY06gIf00=
```

## ssh-ca-client-cli

Part of the [ssh-ca-client-cli](ssh-ca-client-cli.md)
