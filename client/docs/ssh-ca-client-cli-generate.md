## Name

ssh-ca-client-cli-generate - Request and renew host SSH certificates from the Serverless SSH CA

## Synopsis

```sh
ssh-ca-client-cli [global options] generate [--force]
                                            [--dryrun]
```

## Description

Generate a private key or overwrite an existing private key and store the
resulting key in the user configuration location, specified by the `--user`
global option.

## Global Options

See [Options](ssh-ca-client-cli.md#options)

## Options

`--force`
Force overwriting an existing private key.

`--dryrun`
`-n`
Show what would occur but make no changes.

## Examples

* Generate a new private key overwriting any existing key:

  ```sh
  ssh-ca-client-cli generate --force
  ```

* Show any changes that would be made:

  ```sh
  ssh-ca-client-cli generate --force --dryrun
  ```

## ssh-ca-client-cli

Part of the [ssh-ca-client-cli](ssh-ca-client-cli.md)
