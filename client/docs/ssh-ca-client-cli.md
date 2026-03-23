## Name

ssh-ca-client-cli - CLI to interact with the Serverless SSH CA

## Synopsis

```sh
ssh-ca-client-cli [options] [subcommand]                
```

## Options

`--config <path>`
Path to configuration file the defines global/system config such as the CA URL,
OIDC IdP configuration and CA trust.

The default is `/etc/serverless-ssh-ca/config.yml` (Linux/BSD/Darwin) or
`%PROGRAMDATA%\Serverless SSH CA Client\config.yml` (Windows).

`--debug`
Enable debug logging.

`--user <path>`
The path to store user specific configuration (this is ignored for the `host`)
sub-command.

The default is `$HOME/.config/serverless-ssh-ca/user.yaml` (Linux/BSD/Darwin)
or `%APPDATA%\Serverless SSH CA Client\config.yml` (Windows).

## Sub-Commands

`generate`
Generate a SSH private key.

See [ssh-ca-client-generate](ssh-ca-client-generate.md)

`host`
Request and renew SSH host certificates.

See [ssh-ca-client-host](ssh-ca-client-host.md)

`login`
Request user SSH certificates.

See [ssh-ca-client-login](ssh-ca-client-login.md)

`show`
Show user SSH private key, public key and/or certificate.

See [ssh-ca-client-show](ssh-ca-client-show.md)

`version`
Show the current version of the ssh-ca-client-cli

See [ssh-ca-client-show](ssh-ca-client-show.md)
