# 0026 - Classify Token Refresh Failures

## Status

Accepted. Refines ADR 0018 and ADR 0019.

## Context

On 2026-10-22 two Claude Max accounts in the lb-pipeline pool went to `auth_error` within hours of
each other, on the Linux server and on a Mac. Anthropic's token endpoint had answered the refresh
grant with `400 invalid_scope`: the grant replayed the login scope list, including
`org:create_api_key`, which the issuer never grants (fixed upstream in `c58a972`). The refresh
token itself was still good, but `attempt_account` reported every refresh failure as
`AuthFailed`, so a malformed request, a network error or an issuer 5xx stranded a working
subscription until an operator pressed `enable`.

Three further defects surfaced while fixing it:

1. Each request read the access token from the pool's copy of the account, which is only reloaded
   from the store on the housekeeping tick. After a refresh, concurrent and following requests
   saw the expired snapshot and refreshed again, rotating the refresh token once each.
2. The same-account retry after a 401/403 refresh (ADR 0018) used that stale copy, so it resent
   the rejected token; it also consumed one of the request's failover attempts, so with two
   accounts the second was never tried.
3. The Claude usage poll and the boot identity refresh saved whole account rows from snapshots
   taken before a refresh they had just triggered, which could write a rotated-away refresh token
   back to the store.

## Decision

- `tokens::refresh_failure_outcome` decides what a failed refresh does to the account. Only a
  missing refresh token or an issuer error that names a dead credential (`invalid_grant`,
  `invalid_refresh_token`, `refresh_token_reused`, `refresh_token_expired`,
  `refresh_token_invalidated`) is `AuthFailed`. Transport errors, 408, 429 and 5xx cool the account
  for one minute; any other 4xx (`invalid_scope`, `invalid_client`, ...) for fifteen minutes. A
  cooled account keeps its credentials and rejoins the pool when the housekeeping tick sees its
  deadline pass. The scheduled rotation of ADR 0019 still never changes status.
- `force_refresh` retries once with the stored refresh token when the issuer rejects the one it
  submitted but the store meanwhile holds a different one.
- Expiry refreshes go through `refresh_if_expiring`, which rereads the account under the
  per-account lock and returns a token another caller already refreshed. After any refresh the
  proxy reloads that account into the pool.
- A successful forced refresh after a 401/403 returns `Attempt::Refreshed`, which grants the
  same-account retry its own attempt.
- Plan, identity and granted-scope updates use column-scoped store writes that never touch tokens.
  The scope the issuer grants is stored in `accounts.oauth_scope` for diagnosis; underclass never
  sends it back.

## Consequences

- An issuer outage or a protocol mistake now shows as a short `refresh_backoff` cooldown in the
  logs and UI instead of `auth_error`; `auth_error` again means "sign in again".
- A protocol error that never clears (a wrong client id) retries every fifteen minutes per account
  rather than stopping; the logs carry the issuer's sanitized error each time.
- Tests no longer reach the real OpenAI token endpoint: `UNDERCLASS_CODEX_TOKEN_URL` and
  `UNDERCLASS_CLAUDE_TOKEN_URL` point both refresh grants at the e2e mock issuer.
