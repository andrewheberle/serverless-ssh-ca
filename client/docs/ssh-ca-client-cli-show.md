## Name

ssh-ca-client-cli-show - Show any existing private key, public key, certificate or current status.

## Synopsis

```sh
ssh-ca-client-cli [global options] show [--certificate]
                                        [--private]
                                        [--public]
                                        [--status [--json]]
```

## Description

This sub-command can be used to display any exsiting private key, public key or
certificate in Open SSH format based on the contents of the configuration
specified by the `--user` global option.

In addition general status can be displayed showing the existince of any of the
above and the certificate expiry (if one exists).

## Global Options

See [Options](ssh-ca-client-cli.md#options)

## Options

`--certificate`
Display the current certificate if one exists.

`--private`
Display the users private key.

`--public`
Display the users public key.

`--status`
Display general status.

`--json`
Display general status as JSON.

This option is only valid with the `--status` option.

## Examples

* Display the current private key in Open SSH format:

  ```sh
  ssh-ca-client-cli show --private
  ```

* Display the current certificate in Open SSH format:

  ```sh
  ssh-ca-client-cli show --certificate
  ```

* Display the current status as JSON:

  ```sh
  ssh-ca-client-cli show --status --json
  ```

## ssh-ca-client-cli

Part of the [ssh-ca-client-cli](ssh-ca-client-cli.md)
