# ssh-ca-client

This provides the client-side service to interact with the Serverless
Certificate Authority in this repository.

## Installing

```sh
go install github.com/andrewheberle/serverless-ssh-ca/client/cmd/ssh-ca-client@latest
```

## Configuration

The client requires the IdP and CA details set as follows:

```yaml
oidc:
  issuer: OIDC Issuer
  client_id: OIDC Client ID
  scopes: ["openid", "email", "profile"]
  redirect_url: http://localhost:3000/auth/callback
ssh:
  ca_url: https://ca.example.com/
```

The default location for this config file is `$HOME/.ssh-serverless-ca/config`
however this may also be provided using the `--config` command line flag.

## Running

The client can be run in the following ways:

### Generating A Key

To generate a new private key, run as follows:

```sh
ssh-ca-client generate
```

### Show Existing Key/Public Key/Certificate

```sh
ssh-ca-client show [--private] [--certificate]
```

By default the client only displays the users public key, however the
`--private` and `--certificate` options may be provided.

### Requesting a Certificate

To request a certificate from the CA, run the client as follows:

```sh
ssh-ca-client login
```

This will trigger an interactive OIDC authentication flow via the users
web browser to obtain an authentication token, which will be used to perform
a request to the CA for a SSH certificate.

If a refresh token was provided by the OIDC IdP, this will be used initially to
attempt a renewal of the authentication token so the process can avoid an
interactive authentication flow.

## As a GUI

If the client is built with the `tray` build tag and `-ldflags -H=windowsgui`
it can be run as a GUI application that sits in the system tray (this is quite
Windows-centric at this time) and allows generation of a private key and
request/renewal of certificates.

# Attributions

The icons used by the client are made by Freepik from [www.flaticon.com](https://www.flaticon.com).
