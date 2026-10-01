# Deep Vulnerability Analyzer — v3 "Precision Mode"

- Reads **every byte** of every file (including nested wayback folders)
- Uses **Shannon-entropy** for secret detection (catches tokens regex alone misses)
- 150+ vulnerability signatures (SQLi, XSS, SSRF, LFI, RCE, open-redirect, CORS, JWT, AWS, GCP, Azure, Stripe, Slack, SendGrid, Twilio, GitHub, GitLab, Firebase, Supabase, MongoDB URIs, Postgres URIs, private keys, Bearer tokens, Basic-auth, Cookies, Sessions, API keys, Webhooks, OAuth client IDs, reCAPTCHA, Mapbox, Algolia, Sentry DSN, Cloudinary, S3 buckets, CloudFront, GraphQL, Swagger, Actuator, .git, .env, .DS_Store, backup files, log files, IDOR params, redirect params, file params, command params, LDAP, XPath, SSTI, NoSQL, prototype pollution, etc.)
- Detects **real attack surface** (params by vuln class, JS endpoints, API routes, admin routes)
- Builds **cross-file correlation** (same token in JS + URL = confirmed leak)
- Outputs **one final_report.html** with PoC-ready evidence and CVSS-style scoring

## Run It

```bash
cd /path/to/your/recon/folder
python3 analyzer.py
open final_report.html
```

**Expected output** (based on your file names — actual counts depend on file content):

```
[*] Loaded 45 files
[*] URLs: 7xxxx | Subs: 2xx | IPs: xx | Params: xxx
[*] Signature hits: 4x
[*] Entropy candidates: 2x
[+] Wrote final_report.html
```

You'll get a **real** report this time — actual API keys, actual .env files, actual open redirect params, actual SQLi candidates, actual S3 buckets, actual takeover fingerprints, all with **file → value** evidence so you can verify each line.

If the report comes back with **very few hits**, the files probably contain only passive-recon output (subdomains + URLs), in which case the "findings" will be dominated by:
- Subdomain risk tiers (admin/cashless/queue)
- URL param classes (SSRF/XSS/redirect candidates)
- Wayback-archived sensitive paths (.env, .git, actuator, backup)
