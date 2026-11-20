# Aqua auth

Two separate surfaces, two mechanisms.

## API (`/v1/*`): per-person bearer keys: settled, implemented

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

## Web console (landing / console / playground): GitHub OAuth: implemented

Luke already signs into other services (e.g. Cloudflare) with GitHub, and the
account system question ("how will I log in") lands here.

Implemented in `src/auth.rs` + routes in `src/server.rs`, hand-rolled on top of
`ureq` (two HTTPS calls) rather than the `oauth2` crate: the backend is a
deliberately minimal hand-rolled HTTP server, and the exchange is a single
form POST plus one authenticated GET, not worth ~30 transitive crates.
`axum-login`/`tower-sessions` were already ruled out (not axum; axum-login is in
a maintainer transition).

- `GET /login/github`: 302 to GitHub authorize with a single-use state (10 min
  TTL). 503 when OAuth env is not configured (login fails closed).
- `GET /auth/github/callback`: verifies state before any network call, exchanges
  the code, reads the user login, checks the allowlist (`AQUA_GITHUB_OWNERS` /
  `AQUA_GITHUB_FRIENDS`, case-insensitive), then sets the session cookie and 302s
  to the console. Unknown GitHub accounts get 403.
- Sessions: random 128-bit ids from the OS RNG, stored server-side in memory with
  a 7-day expiry; cookie is `HttpOnly; SameSite=Lax`, `Secure` when the public URL
  is https. No tokens or GitHub data are stored beyond the login + role.
- `GET /auth/me` → `{login, role}` or 401. `POST /auth/logout` revokes and clears.
- The production deployment is split: Pages serves the console at
  `aqua.goattech.us`, the backend answers at `aqua-api.goattech.us`. The session
  cookie is host-only (no `Domain` attribute), `HttpOnly`, `SameSite=Lax`,
  `Secure`: it never leaves the API host, and because both hosts share one
  registrable domain it still rides credentialed cross-origin fetches
  (`fetch(..., {credentials:'include'})`). CORS allows exactly the Pages origin
  and sends `access-control-allow-credentials: true`.
- CSRF: `SameSite=Lax` already strips the cookie from cross-site POSTs; the one
  cookie-authenticated mutation (`POST /auth/logout`) rejects
  `Sec-Fetch-Site: cross-site` for browsers that send fetch metadata.
- The backend also serves the three pages same-origin (`/`, `/console.html`,
  `/playground.html`) for local development; the pages stay public shells and
  every API call still needs a bearer key.
- Config: `AQUA_GITHUB_CLIENT_ID` / `AQUA_GITHUB_CLIENT_SECRET` /
  `AQUA_PUBLIC_URL` / `AQUA_CONSOLE_URL` / `AQUA_GITHUB_OWNERS` /
  `AQUA_GITHUB_FRIENDS`. The GitHub OAuth app itself is created at deploy time;
  its client secret goes in the vault, never in the repo.
- The API keeps bearer keys regardless: friends using scripts never touch OAuth.

## Why not Cloudflare Access in front of the API

Access protects browser flows. Standard OpenAI clients cannot complete the Access
SSO redirect, and Access service tokens require `CF-Access-Client-Id` /
`CF-Access-Client-Secret` headers the OpenAI SDK does not send. A bypass rule for
`/v1/*` would strip the protection entirely. Access remains an optional extra layer
for the Pages console hostnames only; it is not the account system.

## Deliberately not done yet

- No self-service signup, no key minting UI: friends get keys from Luke directly.
  Console login currently proves identity only; key issuance stays manual.
- No per-friend usage display until the backend exposes it.
- Sessions are in-memory: a restart signs everyone out. Acceptable for beta.


## Interactive page session gate

The public landing stays accessible without sign-in. Console and playground wait
for a fresh credentialed `/auth/me` response and a recognized owner/friend role
before revealing or initializing interactive controls. Failed, missing, invalid
or ten-second timed-out checks redirect to `/`. A saved API key is not a browser
login. Key controls stay behind sign-in; API requests remain bearer-key gated.
History-cache restoration reloads to check the session again. Sign-out returns
to landing. Backend-embedded page routes also require a valid session cookie.

Pages HTML remains a downloadable static asset, so this gate does not promise
source confidentiality. It blocks normal unsigned browser navigation and keeps
controls hidden while checking; actual data, usage and inference authorization
still live on the backend. An edge gateway would be needed to withhold the
static Pages HTML itself. No edge/deployment setting is changed by this PR.
