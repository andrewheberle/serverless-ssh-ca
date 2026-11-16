# Retry-After on rate-limited responses

When the `RATE_LIMITER` binding refuses a request, the CA answers `429 Too
Many Requests` without a `Retry-After` header, and will keep doing so.

## Why this is out of scope

RFC 6585 lets a 429 include `Retry-After` but doesn't require it, and the
header is only useful if its value is right. The CA has no way to know the
right value:

- The Cloudflare Workers rate limit binding returns only `{ success }`. It
  doesn't say when the limit resets.
- The binding's `period`, 10 or 60 seconds, is set in `wrangler.jsonc` and
  can't be read by the Worker.
- `CaRateLimiter`, the interface any other limiter must match, has the same
  `limit({ key }): Promise<{ success: boolean }>` shape.

The ways around this were each considered and rejected:

- **A fixed value** would be wrong for any configuration it wasn't chosen for.
- **A new setting holding the period** would copy the limiter's own
  configuration, and nothing would notice when the two disagreed.
- **An optional retry time returned by `CaRateLimiter`** would add to the
  package's public interface, but the Workers binding still couldn't provide
  it, so Workers deployments, the main target, would get no header.

No known client reads the header either: ssh-ca-client displays the error
message and lets the user try again.

## What would change this

If the Workers rate limit binding starts reporting when a limit resets, adding
an optional retry time to `CaRateLimiter` and sending it as `Retry-After`
becomes worth doing.

## Prior requests

- #638: split from #605, which listed the missing header among
  inconsistencies in error responses
