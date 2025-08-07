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
issuer: OIDC Issuer
client_id: OIDC Client ID
scopes: ["openid", "email", "profile"]
redirect_url: http://localhost:3000/auth/callback
ca_url: https://ca.example.com/
```

The default location for this config file is `$HOME/.ssh-serverless-ca/config.yml`
however this may also be provided using the `--config` command line flag.

If one of the requested scopes is `offline_access` and this is supported by the
OIDC IdP then the client can use the provided refresh token for subsequent
certificate renewals.

The client saves persistent user data such as the user private key, refresh
token (if provided) and certificate into a user specific configuration file,
which by default is `$HOME/.ssh-serverless-ca/user.yaml` however this can be
overidden using the `--user` command line flag.

This allows the use of a shared/system configuration file that defines the
OIDC and SSH CA configuration with user specific data kept seperate.

## Running via the CLI

The client can be run in the following ways:

### Generating A Key

To generate a new private key, run as follows:

```sh
ssh-ca-client-cli generate
```

### Show Existing Key/Public Key/Certificate

```sh
ssh-ca-client-cli show [--private] [--certificate]
```

By default the client only displays the users public key, however the
`--private` and `--certificate` options may be provided.

### Requesting a Certificate

To request a certificate from the CA, run the client as follows:

```sh
ssh-ca-client-cli login
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

At this time the GUI is only built and packaged for Windows.

# Attributions

The icons used by the client are made by Freepik from [www.flaticon.com](https://www.flaticon.com).
