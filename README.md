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
    AMD_RADEON_MODELS="qwen-3.8-27b=Qwen3.8-27B,deepseek-v4.1-flash=DeepSeek-V4.1-Flash,glm-5.3-flash=GLM-5.3-Flash"
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
gonka is a paid metered service.

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

AMD Radeon Token Factory inference was verified on 2026-11-16. Its points
are usage units, not money or purchased credits. Keys expire after 30 days.
The adapter id is `radeon`, with `AMD_RADEON_API_KEY`, `AMD_RADEON_MODELS`
and `AQUA_STATUS_RADEON`. The retired `AMD_TOKENLAB_*` variables are not read.

Cloudflare Workers AI remains off until the account is verified to have no
paid fallback. Its free allocation is 10,000 neurons/day across models.
Only GLM 4.7 Flash is configured below, and no model marked
`require_workers_paid=true` may be enabled. The account-specific base URL
must be pinned by the deployment configuration; this registry entry does
not enforce account billing limits.

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
    AQUA_PUBLIC_URL=https://aqua-api.goattech.us   # this backend's own public URL (OAuth callback host)
    AQUA_CONSOLE_URL=https://aqua.goattech.us      # where the browser lands after login (Pages)
    AQUA_GITHUB_OWNERS=goattech-42               # GitHub logins, lowercase, comma-sep
    AQUA_GITHUB_FRIENDS=sam,alex
    AQUA_AUTO_SHORTLIST=coder-a,coder-b          # ordered models for the auto alias; empty disables auto
    AQUA_MODEL_META=coder-a=128000               # verified context windows, tokens
    AQUA_UPSTREAM_BUDGET_SECS=300                # aggregate deadline shared by ALL fallback attempts of one request
    OPENROUTER_API_KEY=... ZRO_API_KEY=... etc.
    AQUA_STATUS_CLOUDFLARE=off               # until no-paid-fallback proof
    CLOUDFLARE_AI_BASE_URL=https://api.cloudflare.com/client/v4/accounts/<account-id>/ai/v1
    CLOUDFLARE_API_TOKEN=...
    CLOUDFLARE_MODELS="glm-4.7-flash=@cf/zai-org/glm-4.7-flash"

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
`https://aqua-api.goattech.us` (Cloudflare-proxied record -> Cosmos -> container).
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

## Virtual USD caps

This is usage accounting, not billing. Aqua never buys provider credits. Friends
start at $2/day and $15/month in virtual USD; the owner is tracked but uncapped.
Daily and monthly windows reset at UTC midnight. Prices are list-price benchmarks,
not a promise of what a provider charges. Default input/output USD per million
tokens, checked 2026-11-16:

| Model | Input | Output | Source |
| --- | ---: | ---: | --- |
| glm-5.3 | 1.40 | 4.40 | https://docs.z.ai/guides/overview/pricing |
| glm-5.3-flash | 0.15 | 0.50 | https://docs.z.ai/guides/overview/pricing |
| glm-4.7-flash | 0 | 0 | https://docs.z.ai/guides/overview/pricing |
| deepseek-v4.1-flash-1017 | 0.30 | 1.20 | https://api-docs.deepseek.com/quick_start/pricing/ |
| qwen-3.8-27b | 0.50 | 3.00 | http://docs.modelstudio.console.alibabacloud.com/en/model-studio/qwen3-8-27b |

DeepSeek uses peak, uncached list prices for that dated identity only. Qwen uses
the maker's international price. Unknown models use a conservative 10/30 estimate
and are owner-only by default. Output prices of $10/million or more default to
owner-only. These settings do not claim that hypothetical future models exist.

Configuration:

- `AQUA_SPEND_STATE_PATH`: persistent local JSON ledger, default `aqua-spend.json`.
  Requires Rust 1.89+ for its exclusive OS file lock. One server process per ledger.
  Back up the ledger; deleting it resets usage. A missing parent directory, corrupt
  ledger or competing process prevents startup. Never put it on ephemeral storage.
- `AQUA_SPEND_DEFAULT_CAP=2/15`: daily/monthly virtual USD for friends.
- `AQUA_SPEND_CAPS=sam=2/15,alex=1/10`: initial per-account caps.
- `AQUA_MODEL_PRICES=custom-model=0.15/0.50`: input/output USD per million.
- `AQUA_MODEL_ACCESS=custom-model=admin`: restrict explicitly. `all` explicitly
  permits friends, still subject to provider eligibility and caps.

The admin API has `GET /v1/admin/usage` and `POST /v1/admin/caps` with JSON
`{"name":"sam","daily":"2","monthly":"15"}`. Decimal amounts are strings.
Use the admin bearer key or an owner browser session. Cookie mutations require an
explicit approved Origin and reject cross-site fetches. Owner caps cannot be set.
Names match configured account names, not API tokens. Cap edits persist in the
ledger and take precedence over the initial environment settings.

Before every friend dispatch, Aqua durably reserves a verified context window of
input plus a full output window per completion (n=1..8). Missing verified context
metadata fails closed. Large windows can require a cap larger than one request's
actual cost: no token-estimation shortcut weakens the cap. Successful JSON usage
or a completed SSE usage report replaces the reservation with reported cost.
Missing usage, truncated streams and ambiguous network failures keep the full
hold. Explicit request/auth/model/rate rejections (400, 401, 403, 404, 422, 429)
release it; ambiguous server failures do not. Concurrent requests share the same
account budget. A report above the reserved bound is recorded and blocks further
friend dispatches for that account until the ledger/bound is repaired offline.
Persistence failure also fails closed for friends. Owner requests stay uncapped;
check `accounting_available` and `unknown_requests` before treating totals as
complete. `unknown_owner_requests_since_startup` counts owner admissions skipped
because storage failed, and resets on restart. Audit logs are needed across such
outages. Owner usage cannot be reconstructed when an upstream omits usage.

## November 16 provider intake (registry only, all default OFF)

These adapters add no credentials, enablement or deployment. New variable names
are source mappings, not permission to widen a loader's allowlist. Keep every
new `AQUA_STATUS_*` unset/OFF until its account, model mapping, user scope and
reviewed deployment config are bound together. Shared friend access is not
implied by an owner's successful test; existing per-account restrictions remain.

| Adapter | API base | Key / models environment variables | Exact upstream allowlist |
| --- | --- | --- | --- |
| OrcaRouter | https://api.orcarouter.ai/v1 | `ORCAROUTER_API_KEY` / `ORCAROUTER_MODELS` | `deepseek/deepseek-v4.1-flash-free` only |
| Z.AI standard API | https://api.z.ai/api/paas/v4 | `ZAI_API_KEY` / `ZAI_MODELS` | `glm-4.7-flash`, `glm-4.5-flash` only |
| Inferbase | https://api.inferbase.ai/v1 | `INFERBASE_API_KEY` / `INFERBASE_MODELS` | requested `deepseek-v4-flash` only |

Status variables are `AQUA_STATUS_ORCAROUTER`, `AQUA_STATUS_ZAI` and
`AQUA_STATUS_INFERBASE`. Unknown or paid upstream IDs in these three adapters are
dropped during model parsing, rather than treated as fallback candidates.
Illustrative mappings, not an active environment file:

    ORCAROUTER_MODELS="deepseek-v4.1-flash=deepseek/deepseek-v4.1-flash-free"
    ZAI_MODELS="glm-4.7-flash=glm-4.7-flash"
    INFERBASE_MODELS="deepseek-v4-flash:fp8=deepseek-v4-flash"

Inferbase returned `deepseek-v4-flash:fp8` in its qualified test. Preserve this
build in its public canonical name; do not silently merge it with an unsuffixed
DeepSeek binding. An Orca free suffix is a route requirement, not permission to
remove a model's version. Verify identity before joining any canonical pool.

Z.AI has a fixed local concurrency limit of **one active inference across all
its models**, not one request per minute. A nonblocking account permit is held
through the complete upstream JSON/SSE response and downstream writes; all exits
release it. Local saturation skips that account and may use another binding of
the exact requested model. If no binding succeeds, the existing generic 503/429
rules apply. Local saturation alone returns 503, creates no provider cooldown,
and invents no Retry-After. The permit covers this Aqua server instance only;
other processes or external clients using the same account are outside it.

Qualification evidence received from the server operator on November 16, 2026:
one real inference each succeeded for Zro `deepseek-v4.1-flash`, OrcaRouter's exact
allowlisted route, Z.AI `glm-4.7-flash`, and Inferbase's requested model above.
These are individual route smoke tests, not coding benchmarks or statistical
reliability claims. `glm-4.5-flash` has pricing/catalog evidence only, not a smoke
pass, and is intentionally absent from the example mapping. No new inference
was made while implementing this registry.

- Orca's explicit free alias must stay intact: no paid alias or wallet fallback.
  Standard free limit recorded as 10 RPM / 50 daily requests. Sources:
  https://docs.orcarouter.ai/routing/free-models and
  https://www.orcarouter.ai/api/free-package/public .
- Z.AI's exact two Standard API models had free input/output/cache pricing;
  FlashX, other Flash generations, Coding Plan, tools, paid fallback and top-ups
  are not included. Recorded account balances were zero with auto-recharge off
  and no payment method. Current pricing is not a forever-price guarantee.
  Sources: https://docs.z.ai/guides/overview/pricing and
  https://docs.z.ai/legal-agreement/terms-of-use .
- Inferbase qualification was for the verified existing Google account, not an
  earlier separate account's Playground. Recorded Free plan, zero credit/spend,
  100 requests/day, 5,000/month, 10 RPM, 8,192 input/1,024 output tokens, $0.50/day
  provider-cost allowance. Allowance metering is not paid cost. Its saved policy
  allows Inferbase Managed only, known output price at most $2/million, one
  attempt and no cross-model/direct/BYOK fallback; request-content logging OFF.
  This price-eligibility policy is NOT a permanent no-spend cap after a top-up or
  upgrade. No saved-card list was available to prove historical card absence.
  Keep zero credit and no top-up, upgrade or paid fallback. Sources:
  https://inferbase.ai/docs/api and
  https://inferbase.ai/models/deepseek-v4-flash .
- NextRouter remains parked OFF after Cloudflare 1010 on both tested paths.
  No qualified model, no further workarounds, and no inference that its key is
  invalid. Groq remains held. Neither gets a new active registry route here.
- Existing AMD/NIM/Logfare/OpenRouter and the held Cloudflare registry retain
  their previous gates. Cloudflare remains OFF pending no-paid-fallback proof.

Account balances, policy and free pricing are time-bound evidence. No loader,
secret transport, upgrade, top-up, provider enablement or service start is part
of this source change. Future friend routing still needs verified context
metadata for spend reservations; missing metadata continues to fail closed.
