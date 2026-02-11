# 🛡️ HeaderVet

[![npm version](https://img.shields.io/npm/v/headervet)](https://www.npmjs.com/package/headervet)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

HTTP Security Header checker CLI — **score**, **fix**, and **enforce** security headers.
Like [SecurityHeaders.com](https://securityheaders.com) but for your terminal and CI pipeline, with **copy-paste-ready fix suggestions**.

## Install

```bash
npm install -g headervet
```

## Usage

```bash
# Scan a single URL
headervet https://example.com

# Scan multiple URLs (with summary report)
headervet https://example.com https://github.com

# Read URLs from stdin
cat urls.txt | headervet --stdin

# JSON output
headervet https://example.com --json

# SARIF output (GitHub Security tab integration)
headervet https://example.com --sarif

# CI mode — fail if any URL is below grade B
headervet https://example.com --ci --min-grade B

# Quiet mode — grade only
headervet https://example.com --quiet

# Verbose mode — detailed explanations
headervet https://example.com --verbose

# Authenticated scanning
headervet https://example.com --cookie "session=abc123"

# Custom headers
headervet https://example.com --header "Authorization:Bearer token123"

# Custom User-Agent
headervet https://example.com --user-agent "MyBot/1.0"

# Disable redirect following
headervet https://example.com --no-follow-redirects

# Custom timeout (5 seconds)
headervet https://example.com --timeout 5000
```

## CLI Output Example

```
🔍 https://example.com

  Status   Header                           Score    Severity   Details
  ──────────────────────────────────────────────────────────────────────────────────────────────────────
  ❌ FAIL  Content-Security-Policy          0/15     CRITICAL   Content-Security-Policy header is missing.
                                                                💡 Content-Security-Policy: default-src 'self'; script-src 'self';
                                                                   frame-ancestors 'none'; base-uri 'self'; form-action 'self'; object-src 'none'
  ⚠️  WARN Strict-Transport-Security        7/10     LOW        Missing preload directive.
                                                                💡 Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
  ✅ PASS  X-Frame-Options                  5/5      INFO       X-Frame-Options is set to DENY.
  ✅ PASS  X-Content-Type-Options           5/5      INFO       X-Content-Type-Options is set to nosniff.
  🚫 MISS  Permissions-Policy               0/5      MEDIUM     Permissions-Policy header is missing.
  🚫 MISS  Cross-Origin-Opener-Policy       0/5      LOW        COOP header is missing.
  🚫 MISS  Cross-Origin-Embedder-Policy     0/5      LOW        COEP header is missing.
  🚫 MISS  Cross-Origin-Resource-Policy     0/5      LOW        CORP header is missing.
  ✅ PASS  Referrer-Policy                  5/5      INFO       Referrer-Policy is set to "strict-origin-when-cross-origin".
  ✅ PASS  X-XSS-Protection                 5/5      INFO       X-XSS-Protection disabled (recommended).
  ⚠️  WARN Cache-Control                    3/5      LOW        Cache-Control could be more restrictive.
  ✅ PASS  Set-Cookie                       5/5      INFO       No Set-Cookie header present.
  ⚠️  WARN X-DNS-Prefetch-Control           1/3      LOW        X-DNS-Prefetch-Control header is missing.

  Grade: D
  Score: 41/78 (53%)
```

## What It Checks

| Header | Max Points | Severity | Why It Matters |
|--------|-----------|----------|----------------|
| Content-Security-Policy | 15 | Critical | XSS prevention, code injection, clickjacking |
| Strict-Transport-Security | 10 | Critical | Force HTTPS, prevent downgrade attacks |
| X-Frame-Options | 5 | Medium | Clickjacking protection |
| X-Content-Type-Options | 5 | Medium | MIME sniffing prevention |
| Permissions-Policy | 5 | Medium | Restrict browser features (camera, mic, etc.) |
| Cross-Origin-Opener-Policy | 5 | Low | Cross-origin isolation |
| Cross-Origin-Embedder-Policy | 5 | Low | Cross-origin isolation |
| Cross-Origin-Resource-Policy | 5 | Low | Resource sharing control |
| Referrer-Policy | 5 | Medium | URL leak prevention |
| X-XSS-Protection | 5 | Low | Deprecated — checks for safe config |
| Cache-Control | 5 | Low | Prevent sensitive data caching |
| Set-Cookie | 5 | Medium | Secure/HttpOnly/SameSite attributes |
| X-DNS-Prefetch-Control | 3 | Low | DNS prefetch privacy |

**Total: 78 points**

### CSP Deep Checks

- `default-src` presence
- `unsafe-inline` / `unsafe-eval` detection
- Wildcard source (`*`) detection
- `frame-ancestors` for clickjacking
- `base-uri` restriction (base tag injection)
- `form-action` restriction (form hijacking)
- `object-src` restriction (plugin attacks)
- `script-src` nonce/hash recommendation
- `report-uri` / `report-to` bonus

### HSTS Deep Checks

- `max-age` ≥ 1 year (31536000)
- `includeSubDomains` presence
- `preload` directive

### Cookie Security Checks

- `Secure` flag (HTTPS only)
- `HttpOnly` flag (no JS access)
- `SameSite` attribute (CSRF protection)
- `__Secure-` prefix validation
- `__Host-` prefix validation

## Grading

| Grade | Score |
|-------|-------|
| A+ | ≥ 95% |
| A | ≥ 85% |
| B | ≥ 70% |
| C | ≥ 55% |
| D | ≥ 40% |
| E | ≥ 25% |
| F | < 25% |

## CI Integration

```bash
# Fail pipeline if grade drops below B
headervet https://your-app.com --ci --min-grade B

# Use with JSON for machine parsing
headervet https://your-app.com --ci --json --min-grade A

# Quiet mode for scripts
headervet https://your-app.com --ci --quiet --min-grade B
```

Exit codes:
- `0` — All URLs meet the minimum grade
- `1` — One or more URLs below threshold

### GitHub Actions

```yaml
name: Security Headers
on: [push, pull_request]

jobs:
  headervet:
    runs-on: ubuntu-latest
    steps:
      - name: Security Headers Check
        run: npx headervet https://your-app.com --ci --min-grade B

      # Or with SARIF upload to Security tab
      - name: Security Headers Scan
        run: npx headervet https://your-app.com --sarif > results.sarif
        continue-on-error: true

      - uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif
```

### GitLab CI

```yaml
security-headers:
  stage: test
  image: node:20-alpine
  script:
    - npx headervet https://your-app.com --ci --min-grade B
  rules:
    - if: '$CI_PIPELINE_SOURCE == "merge_request_event"'
    - if: '$CI_COMMIT_BRANCH == "main"'

# With JSON artifact
security-headers-report:
  stage: test
  image: node:20-alpine
  script:
    - npx headervet https://your-app.com --json > headervet-report.json
  artifacts:
    paths:
      - headervet-report.json
    expire_in: 30 days
```

### Multiple URLs in CI

```bash
# Scan multiple endpoints
headervet https://app.example.com https://api.example.com https://admin.example.com --ci --min-grade C

# Or from a file
echo "https://app.example.com
https://api.example.com
https://admin.example.com" | headervet --stdin --ci --min-grade B
```

## Comparison with SecurityHeaders.com

| Feature | HeaderVet | SecurityHeaders.com |
|---------|-----------|-------------------|
| CLI / Terminal | ✅ | ❌ (web only) |
| CI/CD Integration | ✅ | ❌ |
| SARIF Output | ✅ | ❌ |
| JSON Output | ✅ | ❌ |
| Fix Suggestions | ✅ Copy-paste ready | ❌ |
| Set-Cookie Check | ✅ | ✅ |
| CSP Deep Analysis | ✅ (9 sub-checks) | ✅ |
| HSTS Preload Check | ✅ | ✅ |
| Multiple URLs | ✅ (with summary) | ❌ (one at a time) |
| Authenticated Scanning | ✅ (--cookie) | ❌ |
| Custom Headers | ✅ (--header) | ❌ |
| Offline / Private | ✅ | ❌ (sends to server) |
| Redirect Chain Analysis | ✅ | ✅ |
| Severity Levels | ✅ | ❌ |
| Free | ✅ OSS | ✅ (basic) |

## Fix Suggestions

HeaderVet doesn't just flag problems — it tells you exactly what to add:

```
❌ FAIL  Content-Security-Policy         0/15     CRITICAL   Content-Security-Policy header is missing.
                                                             💡 Content-Security-Policy: default-src 'self'; script-src 'self';
                                                                frame-ancestors 'none'; base-uri 'self'; form-action 'self'; object-src 'none'
```

## Options

| Option | Description | Default |
|--------|-------------|---------|
| `--json` | JSON output | off |
| `--sarif` | SARIF output | off |
| `--ci` | CI mode (exit code on failure) | off |
| `--min-grade <grade>` | Minimum grade for CI | C |
| `--stdin` | Read URLs from stdin | off |
| `--timeout <ms>` | Request timeout | 10000 |
| `--follow-redirects` | Follow HTTP redirects | on |
| `--no-follow-redirects` | Disable redirect following | - |
| `--user-agent <string>` | Custom User-Agent | HeaderVet/1.0 |
| `--cookie <string>` | Cookie header | - |
| `--header <key:value>` | Custom header (repeatable) | - |
| `--verbose` | Show detailed explanations | off |
| `--quiet` | Grade-only output | off |

## Development

```bash
git clone https://github.com/taku-tez/HeaderVet.git
cd HeaderVet
npm install
npm run build
npm test
```

## Part of xxVet Series

xxVet is a collection of 15 focused security CLI tools. See [full catalog](https://www.notion.so/xxVet-CLI-304b1e6bcbc2817abe62d4aecee9914a).

## License

MIT
