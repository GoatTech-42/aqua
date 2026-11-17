# Image transport qualification, gate 1

Offline library work only. No provider adapter calls this module. Image catalog
and endpoint behavior remain qualification-locked, including with both switches
set to1. This packet does not enable image generation or authorize deployment.

The generic GET transport accepts only HTTPS image.pollinations.ai and
aihorde.net, with no explicit port or exactly443. There is no allowed storage
host yet. Exact Horde result-host terms and policy are still unresolved; a
wildcard or a guessed result host is not an acceptable substitute.

The URL and pin constructors both reject unexpected authorities, userinfo,
non443 ports, numeric aliases, control bytes, fragments and backslashes. DNS
answers are checked for non-global/private/special IPv4 and IPv6 addresses,
including mapped/well-known NAT64/6to4/Teredo and documentation ranges. The IP policy is
conservative and can reject some usable addresses. A mixed public/private
answer is rejected. A successful resolution pins its first public address;
there is no second resolution, alternate-address rotation, redirect or proxy
connector. The original hostname is kept for SNI, certificate verification and
HTTP Host. No authorization or cookie header is accepted by this GET helper.

A fresh agent uses explicit proxy=None, a TCP then Rustls connector chain, SNI
on, verification on, no redirects, a16KiB response header cap and the caller's
remaining absolute deadline. DNS wait uses at most5seconds of that same budget.
ureq's resolver bounds the caller's wait with a background DNS thread, not a
forcibly cancelled system lookup. This is not a guarantee of DNS-thread
termination. The caller must still enforce its request concurrency permit.

A wrapper after TLS caps pre-decompression HTTP plaintext, including headers
and framing, at2MiB+16KiB. The output reader separately caps decoded body bytes
at2MiB, including without Content-Length. ureq transparently decodes known gzip
and strips those response headers. An Accept-Encoding:identity request alone
cannot disable that behavior. The two byte bounds intentionally cover both
sides, including a gzip stream with many empty blocks and zero decoded output.
These are transfer bounds, not a full image decode or a CPU-hard-limit decoder.

Errors contain fixed categories, not URLs, prompts, job IDs or response bodies.
ureq diagnostic logging and the reverse proxy still need a dedicated redaction
qualification before a prompt-bearing adapter can be wired. The present code
has no enabled caller. No live provider request was used to qualify this packet.

## Evidence

Tests use the actual TCP and Rustls connectors against a loopback TLS fixture
inside a network-disabled build. Only test setup bypasses public-IP admission
to pin that local socket. Tests verify original SNI and Host, successful trusted
TLS, rejection of an untrusted CA and a mismatched hostname, no credential
headers, redirect denial, unknown-length body limits, a pre-decompression gzip
limit and the global body-read deadline. A separate run sets HTTP_PROXY,
HTTPS_PROXY and ALL_PROXY to an unusable local proxy and clears NO_PROXY; the
transport tests must still pass. This proves that fixture route, not public
provider availability or the unknown Horde storage contract.

The checked-in private key is deliberately a non-secret local test fixture.
It must never be used for a real server or account.

## Policy follow-ups

Cancelled Flow is terminal: relaxing strict privacy cannot resume it. This
remains a policy fixture, not actual worker cancellation. Permit owns the
concurrency reservation until drop; normal rate reservations are not refunded.
EWMA is exactly floor((3*old+new)/4), using u128 intermediate arithmetic.
These types are still not wired to external image work.

## Still blocked

Full bounded pre-allocation JPEG/PNG/WebP decode and single-frame/CPU limits;
Horde terms/model license/exact storage-host contract and sharing flags; live
per-action strict-setting rechecks; durable Classic cooldown and restart-clock
handling; Retry-After/challenge behavior; real best-effort cancellation;
logging/redaction qualification; and all provider adapters remain future gates.
Classic and Horde remain UNKNOWN/NON_ZDR. Cloudflare and video remain off.
