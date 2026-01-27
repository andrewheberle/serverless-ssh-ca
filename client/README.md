# ssh-ca-client

This provides the client-side service to interact with the Serverless
Certificate Authority in this repository.

## Installing

There are two versions of the client, one CLI based and the other GUI based both of which
are tested on Windows and Linux.

[![Get it from the Snap Store](https://snapcraft.io/en/dark/install.svg)](https://snapcraft.io/ssh-ca-client)

On Linux the client is available from the Snapcraft store, however at this time
there are additional steps required to allow the snap version access to the SSH
authentication agent socket due to it's strict confinement.

An example wrapper script is located under `scripts/wrapper.sh` that uses
`socat` to listen on a socket in your home directory and proxies any access to
the "real" SSH authentication agent socket.

In addition you must manually connect the following interfaces for this snap:

```sh
# allow access to the Gnome Keyring
sudo snap connect ssh-ca-client:password-manager-service
# connect the home interface to allow access to ssh-agent socket in $HOME
sudo snap connect ssh-ca-client:home
# start via wrapper script
path/to/wrapper.sh
```

Alternatively binary releases for Linux are available from the GitHub Releases page.

On Windows there is an MSI build that includes both the GUI and CLI versions
and is the recommended option for Windows users.

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
# optional (but recommended) SSH public key of CA
trusted_ca: ecdsa-sha2-nistp256 AAAAE2VjZ...
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

### As A Snap

The snap build must be configured as follows:

```sh
sudo snap set ssh-ca-client issuer="OIDC Issuer"
sudo snap set ssh-ca-client client-id="OIDC Client ID"
# This is the default value
sudo snap set ssh-ca-client scopes=openid,email,profile
# This is the default value
sudo snap set ssh-ca-client redirect-url=http://localhost:3000/auth/callback
sudo snap set ssh-ca-client ca-url=https://ca.example.com/
sudo snap set ssh-ca-client trusted-ca="ecdsa-sha2-nistp256 AAAAE2VjZ..."
```

The above commands would generate the same configuration as the YAML example
above.

### Configuration Privacy/Security

On Windows, sensitive data such as the users SSH private key and the OIDC refresh
token are encrypted using the Windows Data Protection API (DPAPI), while on Linux
a random key is generated and saved in the users `login` keyring which is then
used to encrypt this data using AES-GCM.

If this random key is lost or deleted this data cannot be recovered so the user must
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

### User Cerificates

#### Generating a private key

To generate a new private key, run as follows:

```sh
ssh-ca-client-cli generate
```

#### Show Existing Key/Public Key/Certificate

```sh
ssh-ca-client-cli show [--private|--certificate|--public|--status]
```

By default the client only displays the users public key, however the
`--private` and `--certificate` options may be provided or the `--status`
option can be passed to display a summary of the users key/certificate.

#### Requesting a Certificate

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

### Host certificates

The client can request certificates for pre-exisiting SSH host keys using the
`host` sub-command as follows:

```sh
# request certificates
ssh-ca-client-cli host

# renew existing certificates
ssh-ca-client-cli host --renew
```

By default the CLI will attempt to request certificates for the following keys:

* /etc/ssh/ssh_host_rsa_key
* /etc/ssh/ssh_host_ecdsa_key
* /etc/ssh/ssh_host_ed25519_key

Certificates will be saved as `KEYNAME-cert.pub` and can be used by `sshd` by
adding the following to your `sshd_config` (or `/etc/ssh/sshd_conf.d/*.conf`):

```
HostCertificate /etc/ssh/ssh_host_rsa_key-cert.pub
HostCertificate /etc/ssh/ssh_host_ecdsa_key-cert.pub
HostCertificate /etc/ssh/ssh_host_ed25519_key-cert.pub
```

To ensure your ssh client trusts hosts with certificates issued by your CA you
must add the following to your `authorized_keys` file:

```
@cert-authority *.example.com ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdH...
```

The value of `*.example.com` sets what hosts should be trusted when they present
a certificate signed by the specified CA public key (ie the
`ecdsa-sha2-nistp256...` value). It is also possible to have `*` to trust the
CA for all hosts.

By default the CLI will request a certificate with the hostname of the system
you are running the command on, however it is recommeded to include the FQDN
and IP addresses of the host using the `--principals` option as follows:

```sh
ssh-ca-client-cli host --principals hostname,hostname.example.com,192.168.1.1,etc
```

The CA does not currently enforce any restrictions on what principals it will
issue a certificate for at this time.

#### Renewals

If the host possesses a valid (ie unexpired) certificate issued by the CA the
renewal of the certificate can be completed without requiring an interactive
SSO process via OIDC.

The renewed certificate will be issued with identical principals and extensions
as the current certificate with renewals being skipped unless the certificate
has less than 20% of validity left (based on the default of 30-days validity)

This allows the renewal process to be executed via cron as follows:

```crontab
15 1 * * *   root   ssh-ca-client-cli host --renew
```

## As a GUI

The GUI supports the following command line flags:

| Flag              | Type            | Description                                                      |
|-------------------|-----------------|------------------------------------------------------------------|
| `--life`          | `time.Duration` | Lifetime of SSH certificate                                      | 
| `--renew`         | `time.Duration` | Renew once remaining time gets below this value                  |
| `--addr`          | `string`        | Listen address for OIDC auth flow                                |
| `--log`           | `string`        | Path to log file                                                 |
| `--crash`         | `string`        | Path to log file for panics/crashes                              |
| `--config`        | `string`        | Path to configuration file                                       |
| `--user`          | `string`        | Path to user configuration file                                  |
| `--disable-proxy` | `bool`          | Disable proxying of PuTTY Agent (pageant) requests               |
| `--add-on-start`  | `bool`          | Add current key and certificate (if valid) to SSH agent on start |

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
