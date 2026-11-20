# dev ui copy: em-dash cleanup (for QA verdict)

Branch: instinct/dev-copy-emdash, base main 5bbb47a4. House style bans em dashes and
spaced-hyphen dashes in site copy. This patch removes every prose em dash in the dev
ui lineage and normalizes page titles to the accepted live-tree convention.

## Counts (before -> after, em dashes)

- admin.html 6 -> 0
- console.html 3 -> 1 (remaining: no-data placeholder glyph, line 279)
- keys.html 8 -> 1 (remaining: placeholder glyph, line 339)
- landing.html 4 -> 0
- playground.html 10 -> 8 (remaining: placeholder glyphs, lines 238-241, 429, 457, 472, 478)
- settings.html 0 -> 0
- ui/README.md 2 -> 1 (remaining: line 28, which documents the placeholder convention)

22 edits, each applied via unique-anchor string replacement. All script bodies in the
five modified html files pass node --check.

## Rulings applied

1. Titles (admin, console, keys, landing, playground): normalized to the accepted live
   convention 'aqua - <page>' exactly as the combined v2 tree has it (also fixes the
   Aqua/aqua casing drift to match the accepted tree). The remaining spaced hyphen in
   titles is the same borderline class as the 4 kept root-README lines from the docs
   patch. settings.html already matched ('aqua - settings'), unchanged.
2. Prose em dashes: replaced with a period (new sentence) or a colon (label+qualifier).
3. Meta separators: ' · ' per house style (admin ' · uncapped', landing '200 · streamed',
   landing 'aqua · invite-only model gateway').
4. KEPT, flagged for QA ruling: the '—' no-data placeholder glyphs (10 uses: console 1,
   keys 1, playground 8) and the ui/README line that documents that convention.
   Replacing the glyph changes meaning (it reads as 'no value'), so it needs an
   explicit ruling, e.g. keep, or switch to a different placeholder everywhere
   including the live tree.
5. KEPT as not-copy: CSS comment 'aqua shell - shared by...' (4 files) and JS
   arithmetic with ' - ' (3 spots).

## Not in scope

- routing.html / usage.html remain deferred (QA AMEND 8.3).
- instinct/failure-copy-v2 stays untouched as the migration candidate.
- No workflow edit/dispatch, no publish.
