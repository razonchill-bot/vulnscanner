# VulnScan — Web Vulnerability Scanner

A modular, plugin-based web vulnerability scanner built around detection
(not exploitation): every check is read-only or uses a safe, non-destructive
probe to confirm a vulnerability class exists, without ever extracting real
data or causing damage.

**Only scan systems you own or are explicitly authorized to test** (e.g. your
own CTF challenge boxes, a lab environment, or your own applications).

---

## Architecture

```
vulnscan/
├── core/               # engine, HTTP client, target validation, plugin base
├── modules/
│   ├── recon/          # site info, tech/CMS fingerprinting
│   ├── transport/       # security headers, TLS/cert analysis
│   ├── injection/       # reflected XSS, SQL injection (detection-only)
│   ├── config/          # CORS, clickjacking, cookies, sensitive paths
│   └── access_control/  # CSRF token presence
├── risk/                # severity scoring + OWASP Top 10 mapping
├── report/               # HTML report renderer + SQLite scan history
├── webui/                # FastAPI app + dashboard (CLI + web UI both work)
├── tests/                # unit tests using mocked HTTP responses (no network needed)
└── cli.py                # command-line entry point
```

Every module implements the same interface (`ScannerModule.run() -> ModuleResult`),
which means:
- Adding a new vulnerability check is a self-contained ~50-line file, not a
  change to the engine.
- One module crashing (bad response, network hiccup, weird HTML) can't take
  down the whole scan — the engine isolates each module's exceptions.
- Every finding carries an OWASP Top 10 category, a severity, evidence, and
  a remediation suggestion, so the report is directly useful, not just a
  dump of raw data.

## Why detection-only

Every check either reads passively (headers, TLS config, cookies) or uses a
minimal, non-destructive probe (a single quote to trigger a DB error message,
a unique marker string to check for unescaped reflection, a timing-agnostic
boolean comparison). None of them attempt actual data extraction, remote
code execution, or anything that could damage a target. This is deliberate:
it's both the responsible way to build this, and — for a competition — the
more defensible design if judges ask "what happens if you point this at
something in production?"

## Usage

### CLI
```bash
pip install -r requirements.txt
python cli.py --url https://your-target.example --output report.html
# For local CTF VMs on private IP ranges:
python cli.py --url http://10.0.0.5:8080 --allow-private
```

### Web UI
```bash
pip install -r requirements.txt
uvicorn webui.app:app --reload --port 8000
# open http://localhost:8000
```

### Tests
```bash
python3 -m unittest discover tests -v
```

## Current OWASP Top 10 (2021) coverage

| Category | Status |
|---|---|
| A01 Broken Access Control | CSRF token presence (heuristic) |
| A02 Cryptographic Failures | TLS/cert analysis, cookie flags, HTTPS enforcement |
| A03 Injection | Reflected XSS detection, SQL injection detection (error + boolean based) |
| A04 Insecure Design | *not yet covered — see roadmap* |
| A05 Security Misconfiguration | Security headers, CORS, clickjacking, sensitive path discovery |
| A06 Vulnerable Components | Tech/CMS fingerprinting (small signature set — extend freely) |
| A07 Auth Failures | *partially — see roadmap* |
| A08 Data Integrity Failures | *not yet covered — see roadmap* |
| A09 Logging Failures | Not testable from outside the app — manual review only |
| A10 SSRF | *not yet covered — see roadmap* |

## Roadmap — good next modules to add for competition breadth

These are scoped to fit the same `ScannerModule` interface:

- **Subresource Integrity (SRI) check** (A08): parse `<script src=...>` tags
  pointing at third-party CDNs and flag any missing `integrity` attribute.
- **SSRF parameter heuristics** (A10): flag parameters whose names/values
  look like they fetch a URL server-side (`url=`, `callback=`, `webhook=`),
  as candidates for manual SSRF testing.
- **Open redirect detection**: probe redirect-looking parameters
  (`redirect=`, `next=`, `return_to=`) with an external URL and check if the
  app redirects there unvalidated.
- **Rate limiting / brute-force protection** (A04): send a burst of requests
  to a detected login endpoint and check if any throttling kicks in.
- **Subdomain enumeration**: passive recon via certificate transparency logs
  (crt.sh) to map attack surface beyond the single URL scanned.
- **Known-CVE lookup**: replace the hardcoded `KNOWN_VULNERABLE_HINTS` dict
  in `tech_fingerprint.py` with a live query against the NVD API for any
  detected software + version.
- **GraphQL introspection check**: if `/graphql` is reachable, check whether
  introspection is enabled (common misconfiguration leaking full schema).

## Honest limitations (worth knowing before your demo)

- The tech-fingerprinting signature set is intentionally small — treat it as
  a proof-of-concept for the pattern, and add real signatures for whatever
  stack your competition's target apps use.
- CSRF and clickjacking checks are heuristic (static HTML analysis) — apps
  that protect against CSRF via JS-injected headers instead of hidden form
  fields will show a false positive here. Worth mentioning if asked.
- The sensitive-paths list is small by design (fast, low false-positive) —
  a real engagement would pair this with a proper wordlist-based brute-forcer
  (with rate limiting) for deeper coverage.
- SQLi/XSS detection proves the vulnerability *class* exists; it does not
  attempt to determine exploitability depth (e.g. how much data could
  actually be extracted). That's an intentional scope boundary, not a bug.
