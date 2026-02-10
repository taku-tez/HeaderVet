# 🛡️ HeaderVet

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

# Scan multiple URLs
headervet https://example.com https://github.com

# Read URLs from stdin
cat urls.txt | headervet --stdin

# JSON output
headervet https://example.com --json

# SARIF output (GitHub Security tab integration)
headervet https://example.com --sarif

# CI mode — fail if any URL is below grade B
headervet https://example.com --ci --min-grade B
```

## What It Checks

| Header | Max Points | Why It Matters |
|--------|-----------|----------------|
| Content-Security-Policy | 15 | XSS prevention, code injection |
| Strict-Transport-Security | 10 | Force HTTPS, prevent downgrade |
| X-Frame-Options | 5 | Clickjacking protection |
| X-Content-Type-Options | 5 | MIME sniffing prevention |
| Permissions-Policy | 5 | Restrict browser features |
| Cross-Origin-Opener-Policy | 5 | Cross-origin isolation |
| Cross-Origin-Embedder-Policy | 5 | Cross-origin isolation |
| Cross-Origin-Resource-Policy | 5 | Resource sharing control |
| Referrer-Policy | 5 | URL leak prevention |
| X-XSS-Protection | 5 | Deprecated — checks for safe config |
| Cache-Control | 5 | Prevent sensitive data caching |

**Total: 70 points**

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
```

Exit codes:
- `0` — All URLs meet the minimum grade
- `1` — One or more URLs below threshold

### GitHub Actions Example

```yaml
- name: Security Headers Check
  run: npx headervet https://your-app.com --ci --min-grade B
```

### SARIF + GitHub Security Tab

```yaml
- name: Security Headers Scan
  run: npx headervet https://your-app.com --sarif > results.sarif

- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```

## Fix Suggestions

HeaderVet doesn't just flag problems — it tells you exactly what to add:

```
❌ FAIL  Content-Security-Policy         0/15    Content-Security-Policy header is missing.
         💡 Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self';
            img-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'
```

## Development

```bash
git clone https://github.com/taku-tez/HeaderVet.git
cd HeaderVet
npm install
npm run build
npm test
```

## License

MIT
