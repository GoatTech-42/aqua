# Aqua keys and browser sessions

Console and playground call models/chat using the HttpOnly SameSite=Lax session
cookie. No bearer key is needed, generated, pasted, or saved by that request path.
Cookie POSTs require an explicit exact approved Origin and reject cross-site fetch
metadata. The browser supplies Origin; JavaScript does not set it.

## Personal keys

Signed-in users may create up to 16 named keys, list masked metadata and revoke
only their own keys. Generated keys start with `aqua_sk_`, followed by 256 random
bits from the operating system. Entropy failure stops creation. A SHA-256 digest
is stored, never the full key. Names are 1-64 bytes without control characters.
The create response alone contains the full key. Every JSON response is no-store.

- `GET /v1/keys`: session-only, `{data:[{id,name,masked,created,last_used}]}`.
- `POST /v1/keys`: session-only, approved Origin, `{name}`. Returns 201 with the
  metadata and `key` once. Created/last-used values are Unix seconds; unused is null.
- `POST /v1/keys/{id}/revoke`: session-only, approved Origin. Returns
  `{revoked:true}` or 404. Revocation blocks subsequent auth checks, not a request
  already admitted before the revoke.

Bearer keys work on models/chat. Each use checks the current owner/friend login
allowlist. The role is not frozen at creation. Removed logins fail closed.
All quotas and ledgers share one lowercased account name across sessions and keys.
When OAuth allowlists are configured, legacy key labels must match an exact
allowlisted login after case-folding and have that role, or they are rejected.
No alias mapping such as luke to goattech-42 is inferred. Standalone deployments
without any OAuth allowlist retain legacy keys with lowercase labels. Virtual USD and provider account caps
continue through the existing locked ledgers. Personal providers and Zro are never
eligible for friends, even if Zro were accidentally marked friends.

An explicit Authorization header never downgrades to session auth after failure.
The reserved generated-key prefix never falls back to configured legacy keys.
Key-management endpoints never accept bearer-only authority. Keys do not grant
admin authority. Owner browser admin access uses the owner session.

## Persistence and deployment review

The key store is separate from the spend ledger, at the spend path with its
extension replaced by `.keys.json`, with a `.keys.lock` sibling. For example,
`/state/usage.json` uses `/state/usage.keys.json` and `/state/usage.keys.lock`.
No new environment variable is added. A configured writable spend path is required;
without it, key management and generated-key auth fail closed. Startup fails on a
corrupt, oversized, symlinked or locked key store. Newly created files use mode 0600.

Writes clone under a process mutex, write a bounded same-directory new file,
fsync it, rename atomically, fsync the directory, and only then update memory.
Persistence failure disables key operations until restart. Last-used updates are
persisted before authentication succeeds. State has at most 4096 active keys.
Revoked keys are removed. The original key can never be recovered from the store.

Preserve the key store and lock across releases. Older Aqua binaries do not read or
write this separate store, so they cannot resurrect deleted keys by dropping JSON
fields. A rollback loses generated-key and session API support while the older
binary runs, but must not restore an old key-store backup. Re-deploying the new
binary resumes the current revocation state. Spend-ledger downgrade restrictions
from PR15 still apply independently. No provider enablement is part of this change.

## Admin page

Backend `/admin` and `/admin.html` require an owner session before returning HTML.
Nonowners get 403 without the document. Provider metadata, account usage and cap
edits remain backend-protected. Admin HTML is embedded in the backend only. The
Pages artifact must exclude admin.html; only an owner session gets a link pointing
to the API host's `/admin`, not a public static admin page.

Ship the reviewed backend first, then a single pinned Pages bundle containing the
PR13/14 session gate and session API/key UI. Keep browser checks for sign-out,
expired/revoked session, history restoration and blocked origins. The release is
not complete until a signed-in clean browser lists models and completes an allowed
chat, and owner/nonowner admin access is checked. Do not probe a provider solely
for this test without the operator's existing approval.
