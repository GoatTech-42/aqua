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
identity with a sign-out action. Console and playground require a verified owner
or friend browser session before showing or initializing their interactive UI.
Signed-out, failed, malformed or timed-out session checks redirect to public `/`.
Saved API keys do not bypass this page gate. API-key controls remain available
after sign-in because the existing inference API still requires bearer keys.
Direct API clients keep the existing bearer-key behavior.

Cloudflare Pages hosts static HTML: the browser gate is navigation/UI gating,
not confidentiality for the HTML source. Data and inference remain protected by
the backend. Backend-embedded console/playground routes additionally withhold the
HTML and redirect unless the request has a valid session cookie. Static Pages
HTML would need a separately configured edge session gateway to be private.

## Not done yet

- Streaming replies in the playground (backend supports SSE; the composer uses a
  single non-streaming POST for now).
- Live quota/usage display (backend does not expose it).
- Deployment (Cloudflare Pages): these files are not served anywhere yet.
