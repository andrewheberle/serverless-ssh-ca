## Name

ssh-ca-client-cli-host - Request and renew host SSH certificates from the Serverless SSH CA

## Synopsis

```sh
ssh-ca-client-cli [global options] host [--addr <address>]
                                        [--delay <duration>]
                                        [--force]
                                        [--key <key(s)>]
                                        [--life <duration>]
                                        [--principals <principals>]
                                        [--renew]
                                        [--renewat <percent>]
```

## Description

Issues or renews one or more host SSH certificates with the initial request
requiring an OIDC authentication process against the configured IdP and
subsequent renewals being possible using the current (unexpired) certificate.

When renewing using an existing certificate the principals of the certificate
cannot be changed and the requested lifetime cannot be longer than the current
certificate or the configured maximim of the CA.

As this command writes certificates issued for host SSH keys it needs write access to the directory holding the SSH host keys, which by default is `/etc/ssh` so this command should be run as `root`.

## Global Options

See [Options](ssh-ca-client-cli.md#options)

## Options

`--addr <address>`
The local listen address for the OIDC authentication process.

The default is `localhost:3000`.

`--debug`
Enable debug logging/output.

`--delay <duration>`
The provided duration is used to add a delay between requests if more than one
certificate is being requested in one operation.

This is a `duration` so may be provided with the following units:

* `ms` - milliseconds
* `s` - seconds
* `h` - hours

The default is `250ms`

`--force`
Force renewal of existing certificate(s) regardless of the current validity
period left.

`--key <key(s)>`
A list of one or more host keys to request certificates for. This option may be
passed a comma seperate list of keys or may be provided more than once so
`--key /etc/ssh/ssh_host_ed25519_key,/etc/ssh/ssh_host_ecdsa_key`
and `--key /etc/ssh/ssh_host_ed25519_key --key /etc/ssh/ssh_host_ecdsa_key` are
functionally identical.

The default is `/etc/ssh/ssh_host_ed25519_key,/etc/ssh/ssh_host_ecdsa_key,/etc/ssh/ssh_host_rsa_key`

`--life <duration>`
Request or renew a certificate with the sepecified duration.

The accepted minimum and maximum duration is enforced by the CA and for
renewals the duration may not be larger than the current certificate.

The default is `720h` (30 days)

`--principals <principals>`
The principals to request on the issued host certificate.

This option may be passed a comma seperate list of principals or may be
provided more than once.

It is recommended to request the hostname and IP address(es) of the host so
the client can properly verify the host when connecting via SSH.

This option is only valid for an initial certificate request, not a renewal.

The default is the systems hostname.

`--renew`
Attempt to renew any existing certificates using the current certificate as
the authentication source.

A certificate will only be renewed once it has less validity than the
fraction set by the `--renewat` option or if the `--force` option is set.

`--renewat <percent>`
This sets the fraction of the cerificates lifetime that renewal should be
attempted.

This option is a value from zero (0) to (1) and accepts a floating point
value that is treated as a percentage of a certificates validity period.

The default is `0.5`.

## Examples

* Request a certificate with three principals:

  ```sh
  ssh-ca-client-cli host --prinicpals foo,foo.example.com,192.168.1.10
  ```

* Request a certificate with a short lifespan period:

  ```sh
  ssh-ca-client-cli host --life 7d
  ```

* Request a certificate for an ED25519 and ECDSA host key:

  ```sh
  ssh-ca-client-cli host --keys /etc/ssh/ssh_host_ed25519_key --keys /etc/ssh/ssh_host_ecdsa_key
  ```

* Renew existing certificates:

  ```sh
  ssh-ca-client-cli host --renew
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
