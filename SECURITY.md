# Security policy

## Supported versions

Security fixes are made to the latest 1.x release only. Fixes are not
backported to older 1.x releases or to 0.x releases, so upgrade to the latest
release to get them.

| Version        | Supported |
| -------------- | --------- |
| Latest 1.x     | Yes       |
| Older 1.x      | No        |
| 0.x            | No        |

## Reporting a vulnerability

Report vulnerabilities privately through GitHub Security Advisories:
[report a vulnerability](https://github.com/andrewheberle/serverless-ssh-ca/security/advisories/new),
or select **Report a vulnerability** on the repository's **Security** tab.

Do not report vulnerabilities in a public issue, pull request or discussion.

Include as much of the following as you can:

- the package and version affected, and the runtime (Cloudflare Workers or
  Node.js)
- the endpoint, configuration or export involved, and any non-default
  settings
- what an attacker can do, and what they need first (for example a valid
  access token, a captured proof of possession, or admin access)
- steps to reproduce it, or a proof of concept
- any fix or mitigation you suggest

Don't include real private keys, tokens or certificates. Use ones made for the
report.

You should get a reply within a week. Once the issue is confirmed, the fix is
developed in a private fork for the advisory, released, and then the advisory
is published. You are credited in the advisory unless you ask not to be.

## Scope

This policy covers:

- the CA, `@andrewheberle/serverless-ssh-ca` (`packages/core`), including
  its HTTP API, admin UI and database schema
- the test server, `@andrewheberle/serverless-ssh-ca-testing`
  (`packages/testing`). It is a tool for end-to-end tests of clients and must
  not be used as a production CA, so a weakness that only matters if it is
  used as one is not a vulnerability.

Vulnerabilities in the client, ssh-ca-client, are reported to that project
instead, as described in its
[security policy](https://github.com/andrewheberle/ssh-ca-client/security/policy).

Known limits that are accepted by design are not vulnerabilities, unless you
find a way to do more with them than the design describes. These include
replaying a proof of possession to the same request within the allowed time
skew, as described in
[ADR-0006](docs/adr/0006-proofs-of-possession-are-bound-to-the-request.md).
