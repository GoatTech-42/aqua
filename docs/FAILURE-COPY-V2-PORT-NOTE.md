# failure-copy v2 - bounded port onto main's ui lineage (for QA re-verdict)

Branch: instinct/failure-copy-v2-on-dev-lineage. Response to QA AMEND 8.3 on
instinct/failure-copy-v2 (ededd55e): instead of landing the deployed-lineage bytes,
this branch ports the accepted failure-copy v2 delta (patch sha256 4b4da265...) onto
main's own ui lineage. routing.html and usage.html are DEFERRED per QA verdict (no
routes in main; /fonts assets not in delta). instinct/failure-copy-v2 is kept untouched
as the migration candidate.

## Portability table (19 hunks in the accepted delta)

| file | hunks | result |
|---|---|---|
| console.html | 1 | PORTED (2 exact copy edits + 1 adaptive row copy) |
| keys.html | 5 | PORTED in full (13 edits incl. refresh-button feature) |
| playground.html | 3 | PORTED (1 adaptive: carried button.mrow context CSS) |
| settings.html | 2 | NOT PORTABLE - features absent in this lineage |
| routing.html | 5 | DEFERRED per QA (file absent in this lineage) |
| usage.html | 3 | DEFERRED per QA (file absent in this lineage) |

## console.html (3 edits)

- 'could not reach the api at' -> 'could not reach the gateway at' (exact accepted edit).
- status line -> 'the gateway is unavailable right now. reload the page to try again.'
  (exact accepted edit).
- ADAPTIVE: this lineage's row copy was makeRow('backend not reachable', base, ...);
  replaced with the accepted wording makeRow('could not reach the gateway at ' + base,
  'reload the page to try again.', ...). The accepted hunk's old text did not exist here.

## keys.html (13 edits, accepted hunks 1-5 in full)

- CSS: #aqua-refresh[hidden] { display:none; } before .btn (needed: .btn is inline-flex,
  which would override the hidden attribute).
- HTML: refresh button after the aqua-status stateline (this lineage's stateline text
  'loading keys...' kept as-is; out of delta scope).
- 503 copy -> 'the gateway is unavailable right now. try again shortly, or hit refresh.'
- 404 copy -> 'not found. it may already be revoked or removed.' (also removes a
  pre-existing em dash).
- load(): hide refresh on success, reveal on failure. This lineage's failure say-line
  already matched the accepted wording; only the refresh wiring was added.
- Click listener on aqua-refresh before the initial load().

## playground.html (3 edits)

- CSS: added #aqua-stream button.mrow:focus-visible (the accepted hunk) PLUS two carried
  context rules the deployed lineage already had and this one lacks:
  button.mrow { font-family:inherit; background:none; border:0; width:100%; text-align:left; }
  and #aqua-rail button.mrow:focus-visible. Without them the retry buttons render as
  default UA buttons. Flagged for QA as carried context, not delta content.
- Success path: remove a stale #aqua-pg-fail element.
- Failure path: rail message + 'try again shortly.' retry button, mirrored into
  #aqua-stream below 760px (accepted hunk 3 verbatim; this lineage has the same
  stream/.msg/.body structure and placeholder).

## settings.html - NOT PORTABLE (evidence)

This lineage's settings.html is a 205-line minimal implementation (inline script,
settings-form, zdr_only/default_model/show_cost). It has no 503 storage-error copy
(grep: no '503', no 'unavailable', no 'storage') and no resolve widget (no
aqua-resolve-btn, no 'could not reach'). Both accepted settings hunks anchor to
deployed-lineage features that do not exist here. No edit applied; inventing anchors
would be new feature work, not a port.

## Out-of-scope observation (not changed)

This lineage carries pre-existing em dashes in site copy (console 3, keys 8 after this
port, playground 10). House style bans them; the docs patch fixed README/AUTH only.
Candidate for a follow-up slice.

## Verification

- Every edit applied through exact unique-anchor string replacement (13/13 anchors
  found exactly once; script aborted on any miss).
- All <script> bodies extracted from the three modified files pass node --check
  (5/5 blocks).
- No em dashes or spaced-hyphen dashes in any added line.
- Branch does not touch .github/workflows, no dispatch, no merge. routing/usage not added.
