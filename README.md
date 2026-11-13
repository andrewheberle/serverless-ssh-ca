# Serverless SSH CA on Cloudflare Workers

[![Deploy to Cloudflare](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https%3A%2F%2Fgithub.com%2Fandrewheberle%2Fserverless-ssh-ca%2Ftree%2Fmain%2Ftemplate)

[![codecov](https://codecov.io/gh/andrewheberle/serverless-ssh-ca/graph/badge.svg?token=458TXQTUUC)](https://codecov.io/gh/andrewheberle/serverless-ssh-ca)

This repository contains a serverless Certificate Authority (CA) that can be used
to provide signed certificates for SSH users and hosts running on Cloudflare Workers.

Please see [README.md](packages/core/README.md) for further information.

## Supported Platforms

| Runtime | Version | Used by |
| ------- | ------- | ------- |
| Cloudflare Workers | The current runtime, with the `nodejs_compat` compatibility flag | `@andrewheberle/serverless-ssh-ca` deployed as a Worker |
| Node.js | 24 LTS | `createSshCa` with the helpers from `@andrewheberle/serverless-ssh-ca/node`, and `@andrewheberle/serverless-ssh-ca-testing` |

Node.js 24 matches the `engines` field (`>=24.0.0`) of
`@andrewheberle/serverless-ssh-ca-testing`. Later Node.js versions satisfy that
range but are not tested, so they are best effort. The core package has no
`engines` field, because on Workers Node.js only runs the build.

`@andrewheberle/serverless-ssh-ca-testing` can also run the CA under `workerd`
for end-to-end tests of clients. It is a test tool, not a way to run the CA in
production.

Anything else, such as other Node.js versions, Deno, Bun or other runtimes that
are compatible with Workers, is best effort: bug reports are welcome, but no
support is promised.
