## Name

ssh-ca-client-cli-krl - Download a key revocation list (KRL) for use by `ssh`
or `sshd`.

## Synopsis

```sh
ssh-ca-client-cli [global options] krl [--force]
                                       [--host]
                                       [--out]
```

## Description

This sub-command can be used to download a list of revoked certificates in
order to allow `ssh` or `sshd` to reject revoked host or user certificates
respectively.

The downloaded KRL is verified against a SSHSIG signature as long as the
`trusted_ca` option is set in the global/system configuration file.

## Global Options

See [Options](ssh-ca-client-cli.md#options)

## Options

`--force`
Force writing the KRL to the output location even if `trusted_ca` is not set.

This could allow a third party to provide a malicious KRL payload in order to
pevent legitimate connections.

`--host`
Download and parse the host KRL.

Without this option the default is to download and parse the user KRL

`--out`
`-f`
The output file for the verified KRL.

## Examples

* Retrieve host SSH key revocation list and verify the signature:

  ```sh
  ssh-ca-client-cli krl --host
  ```

* Write a key revocation list to a file:

  ```sh
  ssh-ca-client-cli krl --out /etc/ssh/revocation_list
  ```

  In the above example, having the following configuration in
  `/etc/ssh/sshd_config` will cause `sshd` to reject users that present a
  revoked certificate for authentication:

  ```
  RevokedKeys /etc/ssh/revocation_list
  ```

* Write a key revocation list to a file for host keys:

  ```sh
  ssh-ca-client-cli krl --host --out /home/example/.ssh/revocation_list
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
