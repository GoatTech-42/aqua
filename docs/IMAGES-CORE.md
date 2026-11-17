# Image core, qualification locked

This packet adds only owner-authenticated POST /v1/images/generations and
GET /v1/images/models. No image network connector exists in this packet.
The catalog is empty and valid owner requests return503, including when
AQUA_IMAGES_CLASSIC=1 or AQUA_IMAGES_HORDE=1. Both are off when unset. These
switches are requested configuration, not enablement or qualification grants.
No CF/Logfare/video signup, credit, key or connector is added.

Request subset: model=image-auto,prompt,n=1,size=512x512,response_format=b64_json.
Pinned flux and text auto are rejected, not silently changed. No URL response,
artifact store, external job lookup, decoder, SSRF client, or real cancellation
exists. All such behavior remains a hard connector qualification gate.

The module contains pure/fixture-backed admission, ordering, deadline and
privacy-boundary policy, NOT active production network or cancellation code.
Classic reservation currently takes a fixture boolean; this is NOT actual
persistence. A future connector must implement durable process-egress cooldown
before sending, with conservative restart/clock handling. Never claim it
limits other programs on the same IP. The flow cancellation flag is a
best-effort-cancel requirement, NOT confirmation that a worker stopped.

Privacy must be disclosed before future enablement: Classic embeds prompts
in URLs and shared caches, typically up to30days, retrievable by those with the
URL. Horde sends prompts to volunteer workers. Neither is a verified ZDR
route. Disable Horde public gallery/dataset/training sharing, use only anonymous
0000000000, never personal keys. JobIDs and signed storage URLs are bearer
secrets, never public logs/errors/telemetry or caller lookup handles.

Re-read strict privacy before EVERY new prompt-bearing external action incl
fallback. A toggle after send cannot retract it or establish retroactive ZDR.
Cancel an owned pending job best-effort on privacy toggle/disconnect/deadline,
never submit more work. Common request-start+180s, no refreshed windows/hedging.
No 402/payment/challenge/moderation fallback. No IP/key rotation.

Qualification requires actual connecting-client public-IP pinning with correct
SNI/certificate verification, no proxies/env bypass/redirects, exact verified
result hosts, HTTPS443,no userinfo,numeric-host aliases,private/mappedIPv4/IPv6.
Never forward Horde key/cookie to result storage. Current core cannot download
anything, so no SSRF-safe download is claimed yet. Current dependency graph
has no bounded JPEG/PNG/WebP decoder. Magic/MIME/dimensions alone are not enough.
Add a reviewed decoder with header/pixel/byte/CPU bounds BEFORE allocation,
single frame, hard body caps withoutContent-Length. Reject faulted,censored,
csam,zero-result; never evade moderation via fallback. Base64+JSON overhead
must fit the bounded envelope. All current JSON responses/errors are no-store.
Upstream client and reverse-proxy/access-log redaction must also be verified
before any connector enablement; current core has no prompt-bearing HTTPclient.

No image route appears in text models/auto and no text config/schema changed.
Existing owner settings/accounting/revocations are not altered by image
requests. Generated key authentication can persist its normal last-used metadata. HTTP tests prove owner/friend/CSRF/bad-bearer/schema/privacy behavior,
empty image catalog and unchanged quota/health/latency state while off.
Existing full text/auth/routing tests must remain green. No UI changed.

This is NOT deployment-ready or an enabled image service. Watchdog review and
Main exact GO are needed for every later deployment/qualification change.
