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

Currently this command simply downloads and displays a list of revoked user or
host keys in a format that can be consumed by `ssh-keygen` which may then be
referenced in the `ssh` or `sshd` configuration.

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

* Write a key revocation list to a file:

  ```sh
  ssh-ca-client-cli krl | \
    sudo ssh-keygen -k \
      -f /etc/ssh/revocation_list \
      -s /etc/ssh/ca.pub \
      -
  ```

  In the above example, having the following configuration in
  `/etc/ssh/sshd_config` will cause `sshd` to reject users that present a
  revoked certificate for authentication:

  ```
  RevokedKeys /etc/ssh/revocation_list
  ```

* Write a key revocation list to a file for host keys:

  ```sh
  ssh-ca-client-cli krl --host | \
    ssh-keygen -k \
      -f /home/example/.ssh/revocation_list \
      -s /etc/ssh/ca.pub \
      -
  ```

  In the above example, having the following configuration in `~/.ssh/config`
  will cause `sshd` to reject connections to a server with a revoked
  certificate:

  ```
  RevokedKeys /home/example/.ssh/revocation_list
  ```


## ssh-ca-client-cli

Part of the [ssh-ca-client-cli](ssh-ca-client-cli.md)
