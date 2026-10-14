# Authenticate requesters outside request validation

The access token and identity token of a certificate request are verified together by `authenticate` in `packages/core/src/requester.ts`, called from the handler once the request is valid, rather than by Zod transforms in the request schemas. Chanfana validates headers and the body separately, so no schema can see both tokens. The checks that need both (that they are for the same subject, and whether the requester may request host certificates) were therefore repeated in every handler. The handler maps each result to the same status, message and path that request validation used to give, so the response is unchanged and `openapi.json` still documents the tokens as strings.

## Consequences

- A request with other invalid fields is refused before its tokens are verified. Its 400 lists only those fields, and the IdP is not contacted.
- The response messages are relied on by the client's end-to-end tests, so `tests/requester-http.test.ts` pins them for every endpoint that issues a certificate.
