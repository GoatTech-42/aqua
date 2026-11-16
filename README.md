# Aqua (Rust backend)

OpenAI-compatible gateway in front of free AI API providers. Invite-only: Luke and
his friends get Aqua keys; provider keys never leave the server.

## What's public, what's private

- PUBLIC to every user: real model names (`/v1/models`, the `model` field in
  responses and stream chunks). Model maker/name is not a secret.
- ADMIN-ONLY: which serving provider routes each model. Provider ids, base URLs,
  upstream model ids, provider headers, error bodies, and failover metadata never
  reach clients. Errors to clients are generic.
- The public model name never contains the provider id (enforced in config parsing
  and by test). Serving-provider content inside model prose itself is out of scope
  for redaction - the guarantee covers routing metadata, not what a model says.

## Model catalog

Each provider contributes (public, upstream) model pairs via env:

    ZRO_MODELS="deepseek-v4.1-flash=deepseek-v4.1-flash"   # public=upstream, comma-separated
    LOGFARE_MODELS="glm-5.3=glm-5.3,qwen-3.8-27b=qwen-3.8-27b,deepseek-v4.1-flash-1017=deepseek-v4.1-flash-1017"
    # dated model revisions stay distinct; Flash is not the full model
    NVIDIA_NIM_MODELS="deepseek-v4.1-flash=deepseek-ai/deepseek-v4.1-flash,glm-5.3-flash=z-ai/glm-5.3-flash"

Routing is model-first. A specific public model name gathers every eligible
provider carrying that exact model and fails over across those providers only -
a pinned request never drifts to a different model. Unknown names get a generic
400. The reserved `auto` alias walks `AQUA_AUTO_SHORTLIST` (ordered canonical
model names) model by model, provider by provider; with no shortlist configured,
`auto` is disabled rather than delegated to any provider-side router. Cross-model
fallback happens only inside `auto`.

Two providers carrying the same public name are bindings of one canonical model:
the operator must verify the upstream ids really are the same model variant
(same family is not the same model) before reusing a public name.

`AQUA_MODEL_META` attaches verified context windows: `"coder-a=128000"`. The
only local size check is sound: a requested `max_tokens` larger than the window
gets a generic 400 without an upstream call or quota burn. Prompt size is never
estimated (no tokenizer); unknown context means no rejection.

Provider health is passive: real request outcomes cool an account briefly (15s
after errors, 60s after a bare 429), and a provider-sent Retry-After (delta seconds or
IMF-fixdate, bounded to 1h) marks the account hard-limited until it lapses - hard-limited accounts
are never retried, even as a last resort. Cooldowns are account-scope: a 429 on
one model keeps the gateway from hammering that account's other models. No
probing or inference calls are made to test availability.

Public names are operator-configured from each provider's actual model list -
verify against the provider before adding; do not invent ids.

## Stream safety bounds

- Upstream IO carries one aggregate deadline (AQUA_UPSTREAM_BUDGET_SECS,
  default 300s, clamped 1..3600) shared by every fallback attempt of a client
  request: a stall on each candidate cannot multiply the total upstream wait.
- Downstream writes carry the same value as a per-write-operation timeout, so
  a client that stops reading cannot pin a worker (and its in-flight quota
  slot) forever. Healthy long streams are never cut. There is no whole-request
  wall clock: these are IO bounds, not a total deadline.
- The SSE rewriter caps one pending (undelimited) event at 256 KiB, independent
  of how the network chunked it. An upstream that never terminates an event
  gets its stream cut: the client response headers are already committed at
  that point, so there is no failover mid-response - the stream ends honestly,
  without a fabricated [DONE].
- Responses are capped at 4 MiB total, streamed or not.

## Provider policy (every provider ships off)

A "free" label is not proof a route costs nothing. Every provider's default
status is `off`; enable deliberately with `AQUA_STATUS_<ID>=off|personal|friends`
only after cost (no credits, no metered billing) and terms are verified. Status
`friends` means any valid gateway key can use it; `personal` is owner keys only.

Known concerns recorded for the review trail: openrouter free-tier key sharing
for friends not cleared by ToS; zro free plan documented "for your own use";
tokenlab "points" may be credits
and keys expire after 30 days; gonka is a paid metered service.

NIM free inference was verified on 2026-11-16: rate-limited access, no credits
consumed and no per-token billing. NVIDIA describes this access as development
and prototyping. This does not establish permission to share an account or key.
The router honors valid Retry-After headers on rate-limit responses.

Logfare free Standard inference was verified with qwen-3.8-27b on 2026-11-16.
It logs prompts and responses to evaluation datasets (18+, Discord required).
Keep `AQUA_STATUS_LOGFARE=personal`: no sharing the owner's key with friends.
Friends need their own provider connection before they can use this route.
The GLM full, Qwen and dated DeepSeek bindings above come from the verified catalog;
only Qwen inference is verified so far.

## Config (env)

    AQUA_OWNER_KEYS="luke:<key>"        # name:key, comma-separated
    AQUA_FRIEND_KEYS="sam:<key>"
    AQUA_ADMIN_KEY=<key>                # unlocks GET /v1/admin/providers
    AQUA_DAILY_LIMIT=200                # per key per UTC day, atomic reservation
    AQUA_ALLOWED_ORIGIN=https://aqua.goattech.us   # single explicit CORS origin (the Pages console)
    AQUA_BIND=127.0.0.1:8080             # listener; loopback by default, set 0.0.0.0:PORT explicitly at deploy
    # console login (GitHub OAuth; optional - API keys work without it)
    AQUA_GITHUB_CLIENT_ID=<oauth app client id>
    AQUA_GITHUB_CLIENT_SECRET=<oauth app secret>
    AQUA_PUBLIC_URL=https://api.aqua.goattech.us   # this backend's own public URL (OAuth callback host)
    AQUA_CONSOLE_URL=https://aqua.goattech.us      # where the browser lands after login (Pages)
    AQUA_GITHUB_OWNERS=goattech-42               # GitHub logins, lowercase, comma-sep
    AQUA_GITHUB_FRIENDS=sam,alex
    AQUA_AUTO_SHORTLIST=coder-a,coder-b          # ordered models for the auto alias; empty disables auto
    AQUA_MODEL_META=coder-a=128000               # verified context windows, tokens
    AQUA_UPSTREAM_BUDGET_SECS=300                # aggregate deadline shared by ALL fallback attempts of one request
    OPENROUTER_API_KEY=... ZRO_API_KEY=... etc.

Empty or placeholder client keys are dropped at config build and never
authenticate. Provider keys are only ever sent to their own provider.

## API

- `POST /v1/chat/completions` - OpenAI shape, `stream` supported. Whitelisted
  params forwarded: messages, temperature, top_p, max_tokens, stop, n,
  response_format, seed, presence_penalty, frequency_penalty, tools, tool_choice.
  Everything else (including `user`) is dropped.
- `GET /v1/models` - canonical public model names (deduplicated across
  providers, with verified context when known) visible to the caller's role,
  plus `auto` when a shortlist is configured.
- `GET /v1/admin/providers` - admin only: provider ids, statuses, model mappings.

Streaming: SSE parsed per event (multi `data:` lines joined per spec), each chunk
rebuilt from a whitelist; upstream `event:`/`id:`/comment lines and non-SSE 200
bodies never reach the client. Hard 4 MB cap on bytes to the client.

Request framing: HTTP/1.1 with an explicit Content-Length only. Chunked bodies
are rejected with 400 (never guessed); duplicate Content-Length is rejected;
headers over 64 KB are rejected even when terminated. Quota is reserved only
after a request parses and routes - malformed 400s and unroutable 503s never burn
quota. Daily quota counters live in memory and reset on restart (beta). Failed auth
is throttled per token (5/min, then 429) with a bounded failure map.

Logs: one line per request - timestamp, key name, provider id, stream flag.
Prompts and responses are never logged.

## Deployment shape

Split hosting, per the owner's ask: static console on Cloudflare Pages at
`https://aqua.goattech.us`, this Rust backend on his own server at
`https://api.aqua.goattech.us` (Cloudflare-proxied record -> Cosmos -> container).
Same registrable domain, so the host-only `SameSite=Lax` session cookie flows on
credentialed cross-origin fetches; CORS answers exactly one origin with
`access-control-allow-credentials: true`, and cookie-authenticated mutations
additionally reject `Sec-Fetch-Site: cross-site`. The backend still serves the
three pages itself for local dev and same-origin use; Pages is canonical in prod.
The pages pick their API base by hostname (`aqua.goattech.us` -> the `api.` host,
anything else -> same origin), with the localStorage override kept for testing.

## Dev

    cargo test   # 46 tests incl. hostile-upstream redaction probes
    cargo run    # serve
