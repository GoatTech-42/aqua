# Aqua web UI

Static, self-contained pages (no build step): `landing.html`, `console.html`,
`playground.html`. Same dark + aqua identity as the original mockups, now wired to
the real backend.

## Wiring

Each page carries the same small script:

- Base URL: `localStorage.aqua_api_base`, default `<origin>/v1` when served over
  http(s) (same-origin deploy), otherwise the planned production URL. Change it in
  the console footer ("Set base URL").
- API key: `localStorage.aqua_key`, set via "Set API key" (console footer,
  playground top bar). Sent as `Authorization: Bearer` on every call; never leaves
  the browser except to the configured Aqua base URL.

Endpoints used (implemented by the Rust backend):

- `GET {base}/models` → model lists on all three pages.
- `POST {base}/chat/completions` → playground composer (non-streaming for now).

## Honest states

With no key, an unreachable backend, or an empty pool, every panel says so
("No API key set", "not connected", "Pool is empty") instead of showing sample
data. Columns the backend does not expose yet (context size, pricing, quota) show
"—". There is no mock data anywhere in these pages.

## Sign-in

GitHub OAuth console login is implemented (see `docs/AUTH.md`): the backend
serves these pages same-origin, the console reads `/auth/me` to show the signed-in
identity with a sign-out action, and API keys still work without any login. When
no OAuth session exists the console says "API key mode" instead of an identity.

## Not done yet

- Streaming replies in the playground (backend supports SSE; the composer uses a
  single non-streaming POST for now).
- Live quota/usage display (backend does not expose it).
- Deployment (Cloudflare Pages) — these files are not served anywhere yet.
