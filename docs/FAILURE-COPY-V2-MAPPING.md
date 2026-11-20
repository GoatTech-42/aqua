# failure-copy v2 - mapping proposal for QA verdict (temp file, remove after verdict)

Branch: instinct/failure-copy-v2. Proposed landing of the QA-accepted combined tree
(failure-copy unification v2, accepted 9.1) into this repo. Nothing here dispatches the
workflow, touches the pipeline, or publishes anything.

## Artifacts (sha256)

- combined tree tar: 5b88a62054bbeca375b19232603e4c6d43befd5b96f26fad01f9f0d65dbf87b7
- failure-copy patch vs floor candidate: 4b4da2659ca074355580f062fdab8cc066f6ae8094267a31f35bc4b95a39b187
- floor candidate base tar: 67fa37115efac836aafbea36890665592830ea38e5721b26d567eb1ad34c0439
- accepted stacked base (live-byte lineage): tar sha 300cc0f1

## File pins on this branch (sha256)

- ui/console.html  140b834c3b75deb93784fb49a0314d1331ef6da5a3f0e075a058718723d111eb
- ui/keys.html     706f46bb1309e5e37e1f5ce03f4bb11333063af0befda0aa2d5fcfec02ed5479
- ui/playground.html 3b5b99640aa7f3e062d158a36e9a0b7418fb22a242580dae483688ef61e9a547
- ui/routing.html  b8b2815f0d31ce6baf5b2a0e501b2af350ac58f6b1b0fec069fd5ec399e94708 (new file)
- ui/settings.html 797fa33e6a5019b2edfab100ee94e791842037187691bdc9e990d2fab7ec714b
- ui/usage.html    f2c57d9dc6042ff7e86d5ac78eb87c4048e60fa124b46bd4991b50e5e22234a4 (new file)

## Lineage evidence (why QA must verdict the mapping)

1. The accepted console tree derives from the live-site byte lineage, not from this
   repo. Per-file sha256 at main vs the accepted stack base:
   - ui/console.html    repo a819312a vs stack 3902cba5 (682 differing lines)
   - ui/keys.html       repo 06d73b4a vs stack e0163281 (443 differing lines)
   - ui/playground.html repo b770fb11 vs stack 76863599 (504 differing lines)
   - ui/settings.html   repo 5f370b64 vs stack b128600d (980 differing lines)
   The repo versions look like a stripped dev lineage (no font-face blocks, extra
   session-pending style), while the accepted tree is the full deployed rebuild.
2. The frozen pipeline source (ref 8d803fe5, in-repo, Nov 15) contains only
   ui/README.md, ui/console.html, ui/landing.html, ui/playground.html. Its hashes match
   the workflow base manifest. keys/settings/admin/routing/usage do not exist there.
3. The bounded pipeline (aqua-bounded.yml, workflow_dispatch only) pins only
   ui/console.html, ui/landing.html, ui/playground.html in its base/final manifests.
   It checks out the frozen ref, applies two sha-pinned gzipped git deltas, asserts an
   exact final manifest, then builds. A push to main does not feed it, and this branch
   does not modify it. ui/routing.html and ui/usage.html have no place in the pipeline
   manifests as defined today.

## What this branch does

- Overwrites ui/console.html, ui/keys.html, ui/playground.html, ui/settings.html with
  the accepted combined bytes (live-byte lineage + failure-copy v2 + font-floor CSS).
- Adds ui/routing.html and ui/usage.html (new to this repo).
- Adds this mapping note. No workflow changes, no dispatch, no Pages changes.

## Questions for the QA verdict

1. Is overwriting main's stripped ui/ lineage with the deployed-lineage bytes the right
   landing, or should the failure-copy delta be re-based onto main's ui/ lineage instead
   (losing the deployed-lineage features those files carry)?
2. Should routing.html and usage.html live in this repo's ui/ at all, or does prod serve
   them from elsewhere (the "Pages is canonical in prod" path)?
3. If the console bytes should flow through the bounded pipeline, the pipeline needs a
   new embedded delta and final-manifest update covering the ui files. That is a
   workflow edit and a dispatch decision, both out of scope here.
