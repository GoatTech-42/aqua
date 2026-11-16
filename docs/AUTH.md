# Aqua auth

Two separate surfaces, two mechanisms.

## API (`/v1/*`): per-person bearer keys — settled, implemented

Standard OpenAI clients authenticate with `Authorization: Bearer <key>` and nothing
else. Any scheme that adds a second header, a cookie, or an interactive flow breaks
those clients, so the API keeps plain bearer keys.

- Keys are configured server-side: `AQUA_OWNER_KEYS` (full pool) and
  `AQUA_FRIEND_KEYS` (friends-eligible models only). Role gating is enforced in
  `src/server.rs`; provider identity is never exposed to either role.
- `AQUA_ADMIN_KEY` guards `/v1/admin/providers`.
- Keys are issued out of band (Luke hands each friend a key) and rotated by env
  change + restart. Failed-auth throttling is already in place (5 failures / 60s
  per token).
- AQUA_DAILY_LIMIT applies per key.

## Web console (landing / console / playground): GitHub OAuth — recommended next step

Luke already signs into other services (e.g. Cloudflare) with GitHub, and the
account system question ("how will I log in") lands here.

- Add `GET /login/github` + `GET /auth/github/callback` to the Rust backend using
  the `oauth2` crate; session cookie via `tower-sessions` (signed, httpOnly).
  Do not use `axum-login`: the crate is in a maintainer transition
  (https://github.com/maxcountryman/axum-login/discussions/330) and the backend is
  hand-rolled HTTP, not axum.
- Allowlist GitHub usernames via env (`AQUA_ALLOWED_GITHUB_USERS`); Luke's account
  maps to owner role.
- Console login gates the static UI and any future console-only endpoints. The API
  keeps bearer keys regardless — friends using scripts never touch OAuth.

## Why not Cloudflare Access in front of the API

Access protects browser flows. Standard OpenAI clients cannot complete the Access
SSO redirect, and Access service tokens require `CF-Access-Client-Id` /
`CF-Access-Client-Secret` headers the OpenAI SDK does not send. A bypass rule for
`/v1/*` would strip the protection entirely. Access remains an optional extra layer
for the Pages console hostnames only; it is not the account system.

## Deliberately not done yet

- No self-service signup, no key minting UI: friends get keys from Luke directly.
- No per-friend usage display until the backend exposes it.
