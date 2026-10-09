# @andrewheberle/serverless-ssh-ca-testing

Runs the [Serverless SSH CA](../core/README.md) for end-to-end tests of
clients, such as [ssh-ca-client](https://github.com/andrewheberle/ssh-ca-client).

The CA can be run under:

- `node`: Node.js, using the package's Node.js helpers with an in-memory
  `node:sqlite` database
- `workerd`: the Cloudflare Workers runtime, using the Wrangler test harness
  with a local D1 database and Secrets Store, as `wrangler dev` would

Nothing is persisted between runs.

This package is released with `@andrewheberle/serverless-ssh-ca` and uses
whichever version of that package is installed alongside it. To test a client
against an unreleased version of the CA, install a tarball from `npm pack` in
its place.

## Requirements

Node.js 24 or later.

## Usage

```sh
npm install --save-dev @andrewheberle/serverless-ssh-ca @andrewheberle/serverless-ssh-ca-testing
npx serverless-ssh-ca-test-server [--runtime node|workerd] config.json
```

The runtime defaults to `node`. Clients that start the server from another
language can run `node node_modules/@andrewheberle/serverless-ssh-ca-testing/dist/cli.js`,
which avoids the platform-specific shims in `node_modules/.bin`.

The server exits when its standard input is closed, so it does not outlive
the test that started it. If it cannot start, it writes the reason to
standard error and exits with status 1.

## Configuration

The configuration file is a JSON object:

| Property      | Description                                                              |
|---------------|--------------------------------------------------------------------------|
| `private_key` | The CA private key in OpenSSH format                                     |
| `bindings`    | The CA configuration, as the Workers vars (environment variables)        |
| `port_file`   | Path the port is written to once the CA is listening on `127.0.0.1`      |
| `log_file`    | Path that log output from the CA and harness is appended to as JSON lines |

The bindings are those documented for the CA, with every value as a string.
Under `workerd`, Wrangler's working files are written to the directory
containing the configuration file.

## Log file

Each line of the log file is a JSON object with at least `level` and
`message`. Lines logged by the CA are written as they are, and the harness adds
lines whose `message` starts with `harness`:

- `{"level":"info","message":"harness request","method":...,"url":...,"status":...}`
  for every request, where `url` is the path and query. When `status` is 400
  or more, `body` holds the response body, so a test can check why a request
  was rejected.
- `{"level":"error","message":"harness ...",...}` for a fault, meaning the CA
  or harness failed rather than rejected a request. Some faults, such as a
  failure to record an issued certificate, are only visible in the log, so
  tests should fail if any of these lines appear. A CA log line that
  indicates a fault is followed by a line with the message `harness fault`
  and the original line in `line`.

Under `workerd`, the CA's output is copied to the log file every 100ms, so a
request may be logged shortly after its response is received.

## Programmatic use

```ts
import { startTestServer } from "@andrewheberle/serverless-ssh-ca-testing"

const server = await startTestServer("node", "config.json")
// make requests to http://127.0.0.1:${server.port}
await server.close()
```

Under `node` the CA's `console` output is redirected to the log file until the
server is closed.
