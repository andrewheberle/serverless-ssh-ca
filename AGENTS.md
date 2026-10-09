# AGENTS.md

## Project overview
This repository contains a serverless Certificate Authority (CA) that can be used to provide signed certificates for SSH users and hosts running on Cloudflare Workers. The client side component is written in Go and is here: [https://github.com/andrewheberle/ssh-ca-client](https://github.com/andrewheberle/ssh-ca-client)

## Repository layout
- `packages/core/` - @andrewheberle/serverless-ssh-ca
- `packages/core/src/` - main package source
- `packages/core/scripts/` - helper scripts
- `packages/core/tests/` - tests for core package
- `packages/testing/` - @andrewheberle/serverless-ssh-ca-testing; runs the CA under Node.js or workerd for client end-to-end tests. Its command line, configuration file and log format are relied on by the client's end-to-end tests, so keep them compatible and documented in its README.
- `packages/testing/tests/` - unit tests, run against `packages/core/src`
- `packages/testing/integration/` - tests of the built command under both runtimes, run by `npm run test:workers` after `npm run build`
- `packages/workers-integration/` - package used for testing @andrewheberle/serverless-ssh-ca on Workers runtime
- `dist/` - build output; never edit by hand, never commit [unless it's a published artifact]

## Package manager and environment
- Use npm only. Don't create lockfiles for other package managers.
- Node version: [24]. Don't change it unless asked.

## Build, test, lint
Run these before considering any change complete:
- Lint: `npm lint .`
- Test: `npm test`
- Build: `npm build`

Prefer the scripts in `package.json` over invoking tools directly.

## TypeScript conventions
- `strict` mode is on. Don't loosen `tsconfig.json` options to make errors go away.
- No `any`. Use `unknown` and narrow it. No non-null assertions (`!`) or `as` casts unless there's no alternative, with a comment explaining why.
- Model variants as discriminated unions and narrow on the discriminant. Make exhaustive checks with a `never` default case.
- Use `import type` for type-only imports.
- Prefer `const`, small pure functions, and explicit return types on exported functions.

## Runtime validation
- Data crossing a trust boundary (HTTP responses, request bodies, `JSON.parse`, env vars, storage, `postMessage`) is validated with Zod before use.
- Derive static types from schemas with `z.infer<typeof Schema>` rather than declaring them twice.
- Use `safeParse` where failure is expected and handle the error path explicitly.

## Linting
- ESLint uses flat config (`eslint.config.ts`). ESLint needs the root `jiti` devDependency to load TypeScript config files, so keep it. Add ignores to the config's global `ignores` entry, not per-file comments.
- Don't disable rules inline without a comment giving the reason. Never disable rules project-wide to pass a check.

## Documentation
- Exported functions, types, and components get TSDoc comments. Use `{@link Symbol}` for cross-references so they survive renames.

## Testing
- New behaviour needs a test; bug fixes need a test that fails without the fix.
- No real network calls in unit tests; mock at the module boundary.

## Dependencies
- Ask before adding a new dependency. Prefer the platform and standard library.
- Don't upgrade major versions as a side effect of another task.

## Releases
- Releases are prepared by release-please (`release-please-config.json`, `.release-please-manifest.json`), which keeps a `chore(release): vX.Y.Z` PR open with the version bump of the root, core and testing packages and the `CHANGELOG.md` entry, derived from conventional commit messages on `main`.
- Merging the release PR creates the `vX.Y.Z` tag and GitHub release; the tag triggers `.github/workflows/release.yml`, which publishes core and testing to npm and adds `openapi.json` and the SBOM to the release.
- npm trusted publishing is tied to the `release.yml` filename, so don't rename it.
- Don't edit `CHANGELOG.md`, `.release-please-manifest.json` or package versions by hand; release-please maintains them.
- PRs are squash merged with the PR title as the commit message, so PR titles must be conventional commits (`feat:`, `fix(scope):`, `feat!:` for breaking changes); the PR title check enforces this. Only `feat`, `fix`, `perf`, `revert` and breaking changes trigger a release.
- Never delete, move, or force-push an existing tag; fix forward with a new patch version.
- Do not create or push a tag unless specifically directed to as this triggers the release workflow.

## Boundaries
- Don't commit secrets, tokens, or `.env` files.
- Don't edit generated files:
  - `packages/workers-integration/worker-configuration.d.ts`: regenerate with `npm run cf-typegen` if Cloudflare Workers types are outdated after updates to `packages/workers-integration/wrangler.jsonc` or updates to the `wrangler` package.
  - `packages/core/openapi.json` is committed and published in the npm package; the client generates its bindings from it. CI fails if it doesn't match `npm run schema`, so commit the regenerated file with any change that affects it.
- Keep changes scoped to the task. No drive-by refactors or renames.
- Do not change any of the OpenAPI surface as this could break clients.
