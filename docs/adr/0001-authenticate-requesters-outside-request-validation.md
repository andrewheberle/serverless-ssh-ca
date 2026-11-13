# Authenticate requesters outside request validation

The access token and identity token of a certificate request are verified together by `authenticate` in `packages/core/src/requester.ts`, called from the handler once the request is valid, rather than by Zod transforms in the request schemas. Chanfana validates headers and the body separately, so no schema can see both tokens. The checks that need both (that they are for the same subject, and whether the requester may request host certificates) were therefore repeated in every handler. The handler maps each result to the same status, message and path that request validation used to give, so the response is unchanged and `openapi.json` still documents the tokens as strings.

## Consequences

- A request with other invalid fields is refused before its tokens are verified. Its 400 lists only those fields, and the IdP is not contacted.
- The response messages are relied on by the client's end-to-end tests, so `tests/requester-http.test.ts` pins them for every endpoint that issues a certificate.

## Addendum: the status codes are kept at 1.0

The v4 API keeps the status codes this mapping gives a refused certificate request, although some differ from their usual HTTP meaning:

| Situation | Status |
|---|---|
| A token is missing, expired or not valid | 400, with the path of the token (`headers.Authorization` or `body.identity`) |
| The tokens are for different subjects | 403 |
| The requester may not request host certificates | 401 |
| A `lifetime` over the configured maximum | 400 |
| An extension that is not allowed, or no principals | 422 |

Changing them to the usual meanings (401 for a token that is not valid, 403 for a requester that is not permitted) was considered for 1.0. They were kept, because the client's end-to-end tests check them and changing them after 1.0 needs a major release, while the usual meanings would give clients nothing they need. `openapi.json` documents only the codes each operation can return: issuing a user certificate has no 401, as any requester may request one, and renewing a host certificate has no 401 or 403, as it is authorized by a proof of possession rather than by tokens. `tests/openapi-paths.test.ts` pins the documented codes of every operation.
