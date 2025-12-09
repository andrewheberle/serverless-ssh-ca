# ssh-ca-client

[![codecov](https://codecov.io/gh/andrewheberle/serverless-ssh-ca/graph/badge.svg?token=AZLFIBTTFK)](https://codecov.io/gh/andrewheberle/serverless-ssh-ca)

This provides the client-side service to interact with the Serverless
Certificate Authority in this repository.

## Installing

There are two versions of the client, one CLI based and the other GUI based both of which
are tested on Windows and Linux.

On Windows there is an MSI built that includes both the GUI and CLI versions and is the
recommended option for Windows users.

### CLI

```sh
go install github.com/andrewheberle/serverless-ssh-ca/client/cmd/ssh-ca-client-cli@latest
```

### GUI

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

The default location for this config file is
`%PROGRAMDATA%\Serverless SSH CA Client\config.yml` on Windows and
`/etc/serverless-ssh-ca/config.yml` on other plaforms however this may also be
overidden using the `--config` command line flag.

If one of the requested scopes is `offline_access` and this is supported by the
OIDC IdP then the client can use the provided refresh token for subsequent
certificate renewals.

On Windows these system level options can be set using Group Policy via the
ADMX/ADML files in the `policy` sub-directory.

The client saves persistent user data such as the users private key, refresh
token (if available) and certificate into a user specific configuration file,
which by default is `%APPDATA%\Serverless SSH CA Client\config.yml` on Windows
and `$HOME/.config/serverless-ssh-ca/user.yaml` on other platforms however this
can be overidden using the `--user` command line flag.

This allows the use of a shared/system configuration file that defines the
OIDC and SSH CA configuration with user specific data kept seperate.

### Security

On Windows, sensitive data such as the users SSH private key and the OIDC refresh
token are encrypted using the Windows Data Protection API (DPAPI), while on Linux
a random key is generated and saved in the users `login` keyring which is then
used to encrypt this data using AES-GCM.

If this random key is lost or deleted this data cannot be recoved so the user must
regenerate their private key and request a new certificate.

## Requirements

Regardless of the version being run there must be a running `ssh-agent` to handle
private keys, certificates and authentication to your SSH client of choice.

On Windows this requires the `OpenSSH Agent` service to be set to `Manual` start
and `ssh-agent.exe` must be started on login for your user.

On Linux `ssh-agent` should be started as part of your normal login process and in
addition the secure storage of sensitive material requires the users `login` keyring
to be unlocked, which is usually the default in most desktop environments.

## Running via the CLI

The client can be run in the following ways:

### Generating a Key

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

The GUI supports the following command line flags:

| Flag              | Type            | Description                                                      | Default (Windows)                                  | Default (Linux) | 
|-------------------|-----------------|------------------------------------------------------------------|----------------------------------------------------|
| `--life`          | `time.Duration` | Lifetime of SSH certificate                                      | `24h`                                              | 
| `--renew`         | `time.Duration` | Renew once remaining time gets below this value                  | `1h`                                               |
| `--addr`          | `string`        | Listen address for OIDC auth flow                                | `localhost:3000`                                   |
| `--log`           | `string`        | Path to log file                                                 | `%PROGRAMDATA%\Serverless SSH CA Client/tray.log`  |
| `--crash`         | `string`        | Path to log file for panics/crashes                              | `%PROGRAMDATA%\Serverless SSH CA Client/crash.log` |
| `--config`        | `string`        | Path to configuration file                                       | `%APPDATA%\Serverless SSH CA Client/config.yml`    |
| `--user`          | `string`        | Path to user configuration file                                  | `%PROGRAMDATA%\Serverless SSH CA Client/user.yml`  |
| `--disable-proxy` | `bool`          | Disable proxying of PuTTY Agent (pageant) requests               | `false`                                            |
| `--add-on-start`  | `bool`          | Add current key and certificate (if valid) to SSH agent on start | `true`                                             |

The defaults are as follows:

| Flag              | Default (Windows)                                  | Default (Linux)                         | 
|-------------------|----------------------------------------------------|-----------------------------------------|
| `--life`          | `24h`                                              | `24h`                                   | 
| `--renew`         | `1h`                                               | `1h`                                    |
| `--addr`          | `localhost:3000`                                   | `localhost:3000`                        |
| `--log`           | `%PROGRAMDATA%\Serverless SSH CA Client/tray.log`  | `~/.config/serverless-ssh-ca/tray.log`  |
| `--crash`         | `%PROGRAMDATA%\Serverless SSH CA Client/crash.log` | `~/.config/serverless-ssh-ca/crash.log` |
| `--config`        | `%APPDATA%\Serverless SSH CA Client/config.yml`    | `/etc/serverless-ssh-ca/config.yml`     |
| `--user`          | `%PROGRAMDATA%\Serverless SSH CA Client/user.yml`  | `~/.config/serverless-ssh-ca/user.yml`  | 
| `--disable-proxy` | `false`                                            | `true`                                  |
| `--add-on-start`  | `true`                                             | `true`                                  |

# Attributions

The icons used by the client are made by Freepik from [www.flaticon.com](https://www.flaticon.com).
