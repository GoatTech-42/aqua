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
    NVIDIA_NIM_MODELS="llama-3.3-70b=meta/llama-3.3-70b-instruct"

`auto` is a router alias: the gateway tries eligible providers in registry order
(failover). A specific public model name routes only to providers that serve it.
Unknown model names get a generic 400. Public names are operator-configured from
each provider's actual model list - verify against the provider before adding;
do not invent ids.

## Provider policy (defaults are deliberate; restricted providers ship off)

| provider   | default status | why |
|------------|----------------|-----|
| openrouter | personal       | free tier sharing for friends not cleared by ToS |
| zro        | personal       | free plan "for your own use" per zro.moonmath.ai/terms |
| logfare    | off            | logs every prompt/response to eval datasets; 18+; Discord required (logfare.ai/tos) |
| nim        | off            | free trial is internal testing/eval only (NVIDIA API Trial ToS PDF) |
| tokenlab   | off            | "points" may be credits; keys expire after 30 days |
| gonka      | off            | paid metered service |

Override only deliberately: `AQUA_STATUS_<ID>=off|personal|friends`. Status
`friends` means any valid gateway key can use it.

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
    OPENROUTER_API_KEY=... ZRO_API_KEY=... etc.

Empty or placeholder client keys are dropped at config build and never
authenticate. Provider keys are only ever sent to their own provider.

## API

- `POST /v1/chat/completions` - OpenAI shape, `stream` supported. Whitelisted
  params forwarded: messages, temperature, top_p, max_tokens, stop, n,
  response_format, seed, presence_penalty, frequency_penalty, tools, tool_choice.
  Everything else (including `user`) is dropped.
- `GET /v1/models` - `auto` plus public model names visible to the caller's role.
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
