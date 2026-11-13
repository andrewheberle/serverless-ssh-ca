# Serverless SSH CA

A [serverless SSH Certificate Authority](https://github.com/andrewheberle/serverless-ssh-ca)
running on Cloudflare Workers, created with the "Deploy to Cloudflare" button.
This repository holds only the Worker's configuration: the CA itself is the
`@andrewheberle/serverless-ssh-ca` package, and its
[README](https://github.com/andrewheberle/serverless-ssh-ca/blob/main/packages/core/README.md)
describes every setting, the identity provider setup, and how to configure
clients and hosts.

## After deploying

The deploy form creates the D1 database and the Secrets Store secret, and asks
for each setting in `wrangler.jsonc`. Two things are left to do.

### Upload the CA private key

The form cannot keep the line breaks of a private key, so the secret it creates
does not hold a usable key. Create the key, which must not have a passphrase:

```sh
ssh-keygen -t ecdsa -b 256 -N "" -f ca_key
```

Ed25519 keys (`-t ed25519`) work too, and unencrypted PKCS#8 keys are also
accepted. RSA keys are not supported for the CA, although users and hosts may
use them. Then replace the secret's value with the key, using the store and
secret IDs shown in the Cloudflare dashboard:

```sh
npx wrangler login
npx wrangler secrets-store secret update <STORE-ID> --secret-id <SECRET-ID> --remote < ca_key
```

Keep `ca_key` somewhere safe, or delete it: it can sign certificates for any
user or host that trusts the CA.

### Check the deployment

```sh
curl https://<your worker's host name>/api/v4/ca
```

This prints the CA public key, which is what hosts and clients are configured
to trust. A `500` means a setting is not valid: the Worker's logs say which.

## Changing the configuration

Edit `wrangler.jsonc` and commit, and Workers Builds deploys the change. To
serve the CA on your own domain (recommended), uncomment `routes` and set
`workers_dev` to `false`. The landing page and the admin UI are off until
their settings are set; see the CA's README.

Setting the build variable `NODE_VERSION` to `24` in the Worker's build
settings keeps builds on the Node.js version the CA is tested with.

## Upgrading

`package.json` pins the version of the CA. To upgrade, change it to a newer
release and commit. Read the release notes first: a new major version can
need changes to `wrangler.jsonc`. The CA migrates its database automatically,
and an older release cannot run against a database a newer one has migrated,
so take a [D1 Time Travel](https://developers.cloudflare.com/d1/reference/time-travel/)
restore point before upgrading.
