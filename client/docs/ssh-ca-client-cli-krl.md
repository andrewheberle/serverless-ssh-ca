## Name

ssh-ca-client-cli-krl - Download a key revocation list (KRL) for use by `ssh`
or `sshd`.

## Synopsis

```sh
ssh-ca-client-cli [global options] krl [--host]
                                       [--out]
```

## Description

This sub-command can be used to download a list of revoked certificates in
order to allow `ssh` or `sshd` to reject revoked host or user certificates
respectively.

## Global Options

See [Options](ssh-ca-client-cli.md#options)

## Options

`--host`
Download and parse the host KRL.

Without this option the default is to download and parse the user KRL

`--out`
`-f`
The output file for the parse KRL, or `-` to write the text version to stdout. 

## Examples

* Display the a list of revoked host certificates to stdout:

  ```sh
  ssh-ca-client-cli krl --host --out "-"
  ```

## ssh-ca-client-cli

Part of the [ssh-ca-client-cli](ssh-ca-client-cli.md)
