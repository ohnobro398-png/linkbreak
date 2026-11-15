# LINKBREAK — Universal Shortlink Resolver

Paste a short link, find out where it **really** goes. LINKBREAK follows
standard HTTP redirects, records every hop of the redirect chain, and
shows you the final domain — with scam-safety flags — **before** you click.

No fake results, no hardcoded destinations: every resolution happens live
over HTTP.

## What it resolves automatically

| Class | Behaviour |
|---|---|
| Standard HTTP redirects (301 / 302 / 303 / 307 / 308) | Followed hop by hop, up to 10 hops, full chain recorded. |
| Meta-refresh pages (`<meta http-equiv="refresh">`) | Followed as a hop, with the delay shown. |
| Canonical URLs (`rel="canonical"`, `og:url` fallback) | Reported, never silently substituted. |
| Any standard redirect service | Named providers (bit.ly, TinyURL, t.co, is.gd, cutt.ly, Rebrandly, buff.ly, ow.ly, rb.gy, s.id, …) plus brand shortlinks (youtu.be, amzn.to, fb.me, …). Unknown hosts still resolve as `generic` — the registry names providers, it never gatekeeps. |

## What it does NOT do (honest limits)

LINKBREAK never defeats access controls. These are reported, not resolved:

| Class | Behaviour |
|---|---|
| JavaScript challenges / ad-gates (Linkvertise, Adf.ly, ouo.io, shrinkme.io, shorte.st, exe.io, adfoc.us, bc.vc, clk.sh, sh.st, LinkBucks, ity.im, …) | Status `Unsupported` with an explanation. They need a human in a browser. |
| CAPTCHA pages | Reported as `Partially Resolved` / `Failed` — never solved. |
| Login walls, paywalls, DRM | Reported, never bypassed. |
| Deleted / expired links, destinations that block bots | `Partially Resolved` or `Failed`, with the reason shown. |

**Do not claim "all shorteners work":** anything that needs a human to
click, wait, or solve something needs manual completion in a browser.
LINKBREAK tells you that instead of pretending it resolved the link.

## Scam safety

Every result shows, before any click-through:

- **Final domain, prominently** — the hostname the link actually lands on.
- **Brand mismatch flag** — e.g. a link that looks like an `amzn.to`
  short link but lands on a different domain is flagged loudly.
- **Domain-changed note** — the final domain differs from the short
  link's domain (normal for shorteners, but check before clicking).
- **Structural warnings** — bare-IP destination, unencrypted (`http`)
  destination, IDN/punycode domain (homograph risk), `user@host`
  credential tricks.
- **The full redirect chain** — every hop, with method, status, and
  timing, so you can see exactly where the link takes you.

LINKBREAK is not a blocklist and calls no reputation service; it
surfaces the facts in the URLs themselves so *you* can judge.

## Quick start

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --host 127.0.0.1 --port 8000
```

Open `http://127.0.0.1:8000` — single-link resolver, bulk resolver
(up to 20 URLs), history, CSV export, dark/light theme.

History is stored locally in SQLite (`data/linkbreak.db` by default).
Override with the `LINKBREAK_DB` environment variable.

## Docker

```bash
docker build -t linkbreak .
docker run --rm -p 8000:8000 linkbreak
```

## API

### `GET /api/health`

```json
{"status": "ok"}
```

### `POST /api/resolve`

Request:

```json
{"url": "https://httpbin.org/redirect/2"}
```

Response:

```json
{
  "original_url": "https://httpbin.org/redirect/2",
  "detected_provider": "httpbin.org",
  "final_url": "https://httpbin.org/get",
  "redirect_chain": [
    {"url": "https://httpbin.org/redirect/2", "status": 302, "method": "HEAD", "note": null, "elapsed_ms": 120},
    {"url": "https://httpbin.org/relative-redirect/1", "status": 302, "method": "HEAD", "note": null, "elapsed_ms": 95},
    {"url": "https://httpbin.org/get", "status": 200, "method": "HEAD", "note": null, "elapsed_ms": 110}
  ],
  "http_status": 200,
  "resolution_status": "Resolved",
  "error_message": null,
  "elapsed_ms": 325,
  "canonical_url": null,
  "canonical_source": null,
  "original_domain": "httpbin.org",
  "final_domain": "httpbin.org",
  "domain_changed": false,
  "brand_mismatch": false,
  "safety_notes": [
    "Final domain matches the short link's domain (httpbin.org). The destination is on the same site the link came from."
  ]
}
```

Resolution statuses: `Resolved`, `Partially Resolved`, `Blocked`,
`Unsupported`, `Failed`.

### `POST /api/batch-resolve`

Request: `{"urls": ["https://example.com/a", "https://example.com/b"]}`
(max 20 URLs). Response: a list of resolve objects, same shape as above.

### `GET /api/history`

Latest 50 stored resolutions, newest first.

### `DELETE /api/history`

Clears stored history. Response: `{"deleted": N}`.

## Security

- **Only `http://` and `https://`.** Everything else is `Blocked`.
- **SSRF + DNS-rebinding defense.** Every hostname is resolved with
  `socket.getaddrinfo` and checked with `ipaddress` *before* fetching,
  and re-checked on *every* redirect hop. Blocked: `localhost`,
  `127.0.0.0/8`, `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`,
  `::1`, `fe80::/10`, `169.254.0.0/16`, multicast, reserved, and
  unspecified addresses. DNS failures fail closed.
- **No script execution.** Downloaded pages are only parsed (standard
  library `html.parser`) for meta-refresh / canonical tags.
- **Limits.** 10 hops max, 10 s timeout per request, 2 retries on
  transient network errors only, inspected HTML capped at 1 MB, URL max
  2048 chars, batch max 20 URLs, 30 resolve requests/minute per IP
  (in-memory).
- **No secrets in responses.** Error messages never include server
  internals or credentials.

### Sandbox / egress notes (this dev environment only)

Three environment adaptations live in `app/security.py` and
`app/resolver.py` (`build_client()`); on a normal machine they are
no-ops:

1. **Egress NAT range.** Sandbox DNS resolves *all* external hosts
   into `198.18.0.0/15`, which Python's `ip.is_private` marks
   private. That range is explicitly allowed as sandbox egress NAT;
   RFC1918, loopback, link-local, multicast and unspecified stay
   blocked.
2. **Poisoned `no_proxy`.** The sandbox `no_proxy` list contains
   bare IPv6 literals that httpx's `trust_env` parser crashes on
   (`InvalidURL: Invalid port: ':1]'`). The client is built with
   `trust_env=False` and the proxy URL is passed explicitly after
   validation.
3. **Egress MITM CA.** With `trust_env=False`, httpx verifies HTTPS
   against certifi's bundle, which lacks the sandbox egress MITM CA,
   so every HTTPS fetch failed certificate verification. The client
   passes the CA bundle explicitly (`SSL_CERT_FILE` /
   `REQUESTS_CA_BUNDLE` when set, else
   `/run/hatch/egress-tls/ca-bundle.pem` when present, else the
   default).

## Adding a provider

One line in `app/providers.py` — no engine changes:

```python
from app.providers import register_provider
register_provider("short.example", "Example Shortener")
```

For a JS/ad-gated service, register it as unsupported instead:

```python
from app.providers import register_unsupported
register_unsupported("gate.example", "Hides the destination behind a challenge.")
```

## Tests

```bash
pytest -q
```

Covers SSRF blocking (including redirect-to-private), multi-hop chains,
hop limit, meta refresh, canonical / `og:url`, HEAD→GET fallback,
provider registry, safety analysis, and the API (validation, batch
limit, history round-trip). Tests use `httpx.MockTransport` and a fake
DNS resolver — no real network.
