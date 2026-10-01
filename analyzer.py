#!/usr/bin/env python3
"""
Precision Vulnerability Analyzer v3
====================================
Reads every file in the folder (+ nested wayback folders),
performs entropy-based secret detection and 150+ vuln-signature matching,
and writes a single accurate final_report.html
"""

import re, json, math, html, os, hashlib
from pathlib import Path
from collections import defaultdict, Counter
from urllib.parse import urlparse, parse_qs, unquote

# ============================================================
# 0. Config
# ============================================================
ROOT = Path(".")
OUT  = "final_report.html"
SKIP_EXT = {".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
            ".woff", ".woff2", ".ttf", ".otf", ".eot", ".pdf"}

# ============================================================
# 1. Read EVERYTHING
# ============================================================
def all_files():
    for f in ROOT.rglob("*"):
        if not f.is_file(): continue
        if f.suffix.lower() in SKIP_EXT: continue
        if f.name in {"final_report.html", "vulnscan.py"}: continue
        yield f

def read(p):
    try: return p.read_text(encoding="utf-8", errors="ignore")
    except Exception: return ""

CORPUS = {}
for f in all_files():
    CORPUS[str(f)] = read(f)

print(f"[*] Loaded {len(CORPUS)} files")

# ============================================================
# 2. Entropy-based secret detection
# ============================================================
def shannon(s):
    if not s: return 0
    c = Counter(s); n = len(s)
    return -sum((v/n) * math.log2(v/n) for v in c.values())

def is_high_entropy(tok, min_len=16, min_ent=3.5):
    return len(tok) >= min_len and shannon(tok) >= min_ent

# ============================================================
# 3. Signature library — 150+ real vuln patterns
# ============================================================
SIGS = {
    # ---------- Cloud / API keys ----------
    "aws_access_key":     (re.compile(r'\bAKIA[0-9A-Z]{16}\b'), "Critical", "AWS Access Key ID"),
    "aws_secret":         (re.compile(r'(?i)aws[_\-]?secret[_\-]?access[_\-]?key["\'\s:=]{1,5}([A-Za-z0-9/+=]{40})'), "Critical", "AWS Secret Key"),
    "aws_session":        (re.compile(r'\bASIA[0-9A-Z]{16}\b'), "High", "AWS Session Token"),
    "gcp_api":            (re.compile(r'\bAIza[0-9A-Za-z\-_]{35}\b'), "Critical", "Google API Key"),
    "gcp_oauth":          (re.compile(r'\b[0-9]+-[0-9a-z_]{32}\.apps\.googleusercontent\.com\b'), "Medium", "Google OAuth Client ID"),
    "azure_key":          (re.compile(r'(?i)azure[_\-]?key["\'\s:=]{1,5}([A-Za-z0-9+/=]{40,})'), "Critical", "Azure Key"),
    "stripe_live":        (re.compile(r'\bsk_live_[0-9a-zA-Z]{24,}\b'), "Critical", "Stripe Live Secret"),
    "stripe_pub":         (re.compile(r'\bpk_live_[0-9a-zA-Z]{24,}\b'), "Medium", "Stripe Publishable Key"),
    "stripe_test":        (re.compile(r'\bsk_test_[0-9a-zA-Z]{24,}\b'), "Low", "Stripe Test Secret"),
    "paypal":             (re.compile(r'\bA21AA[A-Za-z0-9_\-]{40,}\b'), "Critical", "PayPal Token"),
    "razorpay":           (re.compile(r'\brzp_(live|test)_[A-Za-z0-9]{14,}\b'), "Critical", "Razorpay Key"),
    "square":             (re.compile(r'\bsq0atp-[0-9A-Za-z\-_]{22}\b'), "Critical", "Square Access Token"),
    "twilio_sid":         (re.compile(r'\bAC[a-f0-9]{32}\b'), "High", "Twilio Account SID"),
    "twilio_auth":        (re.compile(r'(?i)twilio[_\-]?auth[_\-]?token["\'\s:=]{1,5}([a-f0-9]{32})'), "Critical", "Twilio Auth Token"),
    "sendgrid":           (re.compile(r'\bSG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}\b'), "Critical", "SendGrid API Key"),
    "mailgun":            (re.compile(r'\bkey-[0-9a-zA-Z]{32}\b'), "High", "Mailgun Key"),
    "mailchimp":          (re.compile(r'\b[0-9a-f]{32}-us[0-9]{1,2}\b'), "High", "Mailchimp Key"),
    "slack_token":        (re.compile(r'\bxox[baprs]-[0-9A-Za-z\-]{10,}\b'), "Critical", "Slack Token"),
    "slack_webhook":      (re.compile(r'https://hooks\.slack\.com/services/T[A-Z0-9]{8,}/B[A-Z0-9]{8,}/[A-Za-z0-9]{24}'), "High", "Slack Webhook"),
    "discord_webhook":    (re.compile(r'https://discord(?:app)?\.com/api/webhooks/\d{17,20}/[A-Za-z0-9_\-]{60,}'), "High", "Discord Webhook"),
    "telegram_bot":       (re.compile(r'\b\d{8,10}:[A-Za-z0-9_\-]{35}\b'), "High", "Telegram Bot Token"),
    "github_token":       (re.compile(r'\bgh[pousr]_[A-Za-z0-9]{36,}\b'), "Critical", "GitHub Token"),
    "gitlab_token":       (re.compile(r'\bglpat-[A-Za-z0-9_\-]{20,}\b'), "Critical", "GitLab Token"),
    "npm_token":          (re.compile(r'\bnpm_[A-Za-z0-9]{36}\b'), "Critical", "NPM Token"),
    "pypi_token":         (re.compile(r'\bpypi-[A-Za-z0-9_\-]{50,}\b'), "Critical", "PyPI Token"),
    "heroku_api":         (re.compile(r'(?i)heroku[a-z0-9_]*["\'\s:=]{1,5}([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})'), "High", "Heroku API Key"),
    "digitalocean":       (re.compile(r'\bdop_v1_[a-f0-9]{64}\b'), "Critical", "DigitalOcean Token"),
    "shopify":            (re.compile(r'\bshpat_[a-f0-9]{32}\b'), "Critical", "Shopify Token"),
    "algolia_admin":      (re.compile(r'(?i)algolia[_-]?(?:admin|api)[_-]?key["\'\s:=]{1,5}([a-f0-9]{32})'), "Critical", "Algolia Admin Key"),
    "algolia_search":     (re.compile(r'(?i)algolia[_-]?search[_-]?key["\'\s:=]{1,5}([a-f0-9]{32})'), "Medium", "Algolia Search Key"),
    "mapbox":             (re.compile(r'\bpk\.eyJ[A-Za-z0-9_\-]{60,}\b'), "Medium", "Mapbox Token"),
    "cloudinary":         (re.compile(r'\bcloudinary://[0-9]{15}:[A-Za-z0-9_\-]{20,}@[a-z0-9]+'), "Critical", "Cloudinary URL"),
    "sentry_dsn":         (re.compile(r'https://[a-f0-9]{32}@o\d+\.ingest\.sentry\.io/\d+'), "Medium", "Sentry DSN"),
    "firebase_api":       (re.compile(r'\bAIza[0-9A-Za-z\-_]{35}\b'), "Critical", "Firebase API Key"),
    "firebase_db":        (re.compile(r'https://[a-z0-9\-]+\.firebaseio\.com'), "Medium", "Firebase Realtime DB"),
    "supabase":           (re.compile(r'https://[a-z0-9]{20}\.supabase\.co'), "Medium", "Supabase URL"),
    "supabase_key":       (re.compile(r'\beyJ[A-Za-z0-9_\-]{20,}\.eyJ[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{20,}'), "High", "JWT / Supabase Key"),
    "okta_token":         (re.compile(r'\b00[A-Za-z0-9_\-]{40}\b'), "High", "Okta Token"),
    "s3_bucket":          (re.compile(r'\b[a-z0-9.\-]{3,63}\.s3(?:[.\-][a-z0-9\-]+)?\.amazonaws\.com\b'), "Medium", "S3 Bucket"),
    "cloudfront":         (re.compile(r'\b[a-z0-9]{14}\.cloudfront\.net\b'), "Info", "CloudFront Dist"),
    "db_uri_mongo":       (re.compile(r'mongodb(?:\+srv)?://[^"\s\'<>]{10,}'), "Critical", "MongoDB URI"),
    "db_uri_postgres":    (re.compile(r'postgres(?:ql)?://[^"\s\'<>]{10,}'), "Critical", "PostgreSQL URI"),
    "db_uri_mysql":       (re.compile(r'mysql://[^"\s\'<>]{10,}'), "Critical", "MySQL URI"),
    "db_uri_redis":       (re.compile(r'redis://[^"\s\'<>]{10,}'), "High", "Redis URI"),
    "private_key":        (re.compile(r'-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----'), "Critical", "Private Key"),
    "pgp_key":            (re.compile(r'-----BEGIN PGP (?:PRIVATE|PUBLIC) KEY BLOCK-----'), "High", "PGP Key"),
    "ssh_key":            (re.compile(r'\bssh-rsa AAAA[A-Za-z0-9+/=]{100,}'), "High", "SSH Public Key"),
    "jwt":                (re.compile(r'\beyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b'), "High", "JWT Token"),
    "bearer":             (re.compile(r'(?i)\bAuthorization\s*:\s*Bearer\s+([A-Za-z0-9\-._~+/]{20,}=*)'), "High", "Bearer Token"),
    "basic_auth":         (re.compile(r'(?i)\bAuthorization\s*:\s*Basic\s+([A-Za-z0-9+/=]{16,})'), "High", "Basic Auth"),
    "url_basic_auth":     (re.compile(r'https?://[^:/\s"\']+:[^@/\s"\']{4,}@[^/\s"\']+'), "High", "Credentials in URL"),
    "google_maps":        (re.compile(r'\bAIza[0-9A-Za-z\-_]{35}\b'), "Medium", "Google Maps Key"),
    "recaptcha_site":     (re.compile(r'\b6L[0-9A-Za-z_\-]{38}\b'), "Low", "reCAPTCHA Site Key"),
    "recaptcha_secret":   (re.compile(r'\b6L[0-9A-Za-z_\-]{38}\b'), "High", "reCAPTCHA Secret"),
    "smtp_creds":         (re.compile(r'(?i)smtp://[^:]+:[^@]+@'), "Critical", "SMTP Credentials"),
    "ftp_creds":          (re.compile(r'(?i)ftp://[^:]+:[^@]+@'), "Critical", "FTP Credentials"),

    # ---------- Web vulnerabilities ----------
    "sqli_param":         (re.compile(r'[?&](id|uid|pid|nid|cat|catid|item|product|page|sel|mode|type|search|query|q|s|keyword|filter|order|sort|by|column|table|field|where|select|report|view|action|cmd|exec)='), "High", "SQLi Candidate Param"),
    "sqli_payload":       (re.compile(r'(?:\'|\%27)\s*(?:or|OR|and|AND)\s+(?:\d+|\'1\'|\"1\")=\s*(?:\d+|\'1\'|\"1\")'), "Critical", "SQLi Payload in URL"),
    "union_select":       (re.compile(r'(?i)union(?:\s|\+|%20)+(?:all(?:\s|\+|%20)+)?select'), "Critical", "UNION SELECT Payload"),
    "xss_param":          (re.compile(r'[?&](q|s|search|query|keyword|name|title|msg|message|text|comment|content|body|desc|description|email|url|redirect|callback|jsonp|next|return|returnUrl|return_url|continue|dest|destination|target|redir|redirect_uri|r|u|link|src|source|ref|referrer|from|to|goto|go|out|view|file|path|dir|folder|page|template|lang|locale|country|city|zone|category)='), "High", "XSS/Redirect/Injection Param"),
    "xss_payload":        (re.compile(r'(?i)(?:%3C|<)\s*script|javascript:|onerror\s*=|onload\s*=|onmouseover\s*=|alert\s*\(|prompt\s*\(|confirm\s*\(|document\.cookie|document\.domain|eval\s*\('), "Critical", "XSS Payload in URL"),
    "ssrf_param":         (re.compile(r'[?&](url|uri|link|src|source|dest|destination|redirect|redirect_uri|return|returnUrl|return_url|next|continue|target|callback|webhook|feed|host|proxy|fetch|load|file|path|resource|reference|ref|image|img|avatar|thumbnail|preview|view|show|open|read|include|require|import|template|layout|page)=', re.I), "High", "SSRF/Redirect Param"),
    "ssrf_meta":          (re.compile(r'(?:169\.254\.169\.254|metadata\.google\.internal|metadata\.azure\.com|100\.100\.100\.200|localhost|127\.0\.0\.1|0\.0\.0\.0|\[::1\]|file://|gopher://|dict://|ftp://)'), "Critical", "SSRF Payload / Internal Addr"),
    "lfi_param":          (re.compile(r'[?&](file|filename|path|dir|folder|include|inc|require|req|page|template|layout|view|show|doc|document|root|load|read|src|source|url|uri|link|download|upload|attach|attachment|resource|resource_path|module|mod|config|conf|lang|locale)='), "High", "LFI/RFI Candidate Param"),
    "lfi_payload":        (re.compile(r'(?:\.\./|\.\.\\|%2e%2e%2f|%2e%2e/|\.\.%2f|%252e%252e%252f|\.\.%5c)'), "Critical", "Path Traversal Payload"),
    "rce_param":          (re.compile(r'[?&](cmd|exec|execute|command|run|system|shell|bash|sh|ping|host|ip|domain|target|daemon|process|proc|pid|kill|service|action|op|do|task|job|worker|scheduler|batch|cron|eval|evaluate|assert|debug|test|check|validate|verify|verify_email|activate|deactivate)='), "High", "RCE Candidate Param"),
    "rce_payload":        (re.compile(r'(?:;|\||`|\$\(|\$\{|%3b|%7c|%60)(?:ls|cat|id|whoami|uname|wget|curl|nc|bash|sh|python|perl|php|ruby)'), "Critical", "RCE Payload"),
    "ssti_param":         (re.compile(r'(?:\{\{|\$\{|<%|#\{|%7b%7b|%24%7b)'), "High", "SSTI Payload"),
    "ldap_param":         (re.compile(r'[?&](user|username|login|uid|cn|dn|filter|search|query|q|s)='), "Medium", "LDAPi Candidate"),
    "xpath_param":        (re.compile(r'[?&](xpath|query|q|s|search|xml|node|select)='), "Medium", "XPath Injection Candidate"),
    "nosql_param":        (re.compile(r'[?&](username|password|user|pass|email|login|id|_id|filter|query|where|field|key|token|session)='), "Medium", "NoSQLi Candidate"),
    "open_redirect":      (re.compile(r'[?&](redirect|redirect_uri|redirect_url|redirecturl|return|returnUrl|return_url|returnurl|next|nextUrl|next_url|url|uri|link|dest|destination|target|redir|r|u|go|goto|out|view|continue|callback|callbackUrl|callback_url|forward|to)='), "High", "Open Redirect Param"),
    "open_redirect_pay":  (re.compile(r'[?&](?:redirect|return|next|url|target|dest|goto)=https?[:/]', re.I), "High", "Open Redirect Payload"),
    "crlf_param":         (re.compile(r'%0d%0a|%0D%0A|\r\n|\n\r'), "High", "CRLF Injection Payload"),
    "prototype_pollution":(re.compile(r'(__proto__|constructor\[prototype\]|prototype\[|\[__proto__\])'), "High", "Prototype Pollution"),
    "graphql":            (re.compile(r'/(?:graphql|graphiql|gql|v1/graphql|api/graphql|query|mutation|__schema|__type)'), "Medium", "GraphQL Endpoint"),
    "graphql_intro":      (re.compile(r'__schema\s*\{|__type\s*\(|\{__typename\}'), "High", "GraphQL Introspection"),
    "swagger":            (re.compile(r'/(?:swagger|api-docs|openapi|redoc|docs)(?:\.json|\.yaml|\.yml)?$'), "Medium", "Swagger / OpenAPI Docs"),
    "actuator":           (re.compile(r'/(?:actuator|env|health|info|metrics|trace|heapdump|threaddump|logfile|jolokia|httptrace|beans|mappings|configprops|auditevents|scheduledtasks|shutdown)(?:/|$|\.json)'), "Critical", "Spring Actuator"),
    "jenkins":            (re.compile(r'/(?:jenkins|script|computer/api|api/json)'), "High", "Jenkins Panel"),
    "git_exposure":       (re.compile(r'/\.git/(?:HEAD|config|index|logs/HEAD|refs/heads/)'), "Critical", ".git Directory"),
    "svn_exposure":       (re.compile(r'/\.svn/(?:entries|wc\.db)'), "High", ".svn Directory"),
    "hg_exposure":        (re.compile(r'/\.hg/(?:requires|store)'), "High", ".hg Directory"),
    "env_file":           (re.compile(r'(?:^|/)(?:\.env|\.env\.\w+|env\.json|env\.yaml|env\.yml)(?:$|[/?#])'), "Critical", ".env File"),
    "backup_file":        (re.compile(r'\.(?:bak|backup|old|orig|swp|swo|tmp|temp|save|copy|~)(?:$|[/?#])'), "High", "Backup File"),
    "config_file":        (re.compile(r'/(?:config|conf|settings|setup|install|wp-config|web\.config|app\.config|application\.yml|application\.properties|bootstrap\.yml|\.htaccess|\.htpasswd|\.npmrc|\.dockerignore|Dockerfile|docker-compose\.yml)(?:$|[/?#])'), "High", "Config File"),
    "log_file":           (re.compile(r'\.log(?:$|[/?#])|/logs?/'), "Medium", "Log File"),
    "ds_store":           (re.compile(r'/\.DS_Store$'), "Medium", ".DS_Store"),
    "phpinfo":            (re.compile(r'/(?:phpinfo|info)\.php'), "High", "phpinfo() Exposed"),
    "phpmyadmin":         (re.compile(r'/(?:phpmyadmin|pma|mysql|adminer|myadmin|dbadmin)/'), "High", "DB Admin Panel"),
    "cpanel":             (re.compile(r'/(?:cpanel|whm|webmail|roundcube|squirrelmail|horde)/'), "High", "cPanel / Webmail"),
    "jira_confluence":    (re.compile(r'/(?:jira|confluence|wiki|bitbucket|bamboo|stash|jfrog|artifactory|nexus|sonar)/'), "High", "Atlassian / DevOps Tool"),
    "kibana":             (re.compile(r'/(?:kibana|app/kibana|elasticsearch|elastic)/'), "High", "Kibana / Elasticsearch"),
    "grafana":            (re.compile(r'/(?:grafana|dashboard|d/\w{12})/'), "High", "Grafana"),
    "prometheus":         (re.compile(r'/(?:prometheus|graph|targets|rules|alerts|metric)/'), "Medium", "Prometheus"),
    "rabbitmq":           (re.compile(r'/(?:rabbitmq|api/overview|api/queues|api/exchanges)/'), "High", "RabbitMQ Management"),
    "redis_web":          (re.compile(r'/(?:redis|redis-commander|redisinsight)/'), "High", "Redis Web UI"),
    "mongo_web":          (re.compile(r'/(?:mongo-express|mongoadmin|mongoclient)/'), "High", "MongoDB Web UI"),
    "docker_registry":    (re.compile(r'/v2/_catalog'), "Critical", "Docker Registry"),
    "kubernetes_api":     (re.compile(r'/api/v1/namespaces|/apis/apps/v1|/version'), "High", "Kubernetes API"),
    "k8s_dashboard":      (re.compile(r'/(?:k8s|kubernetes)/'), "High", "Kubernetes Dashboard"),
    "etcd":               (re.compile(r'/v2/keys|/v3/kv/range'), "Critical", "etcd API"),
    "consul":             (re.compile(r'/(?:consul|v1/kv|v1/catalog)/'), "High", "Consul UI/API"),
    "vault":              (re.compile(r'/(?:vault|v1/sys|v1/secret|v1/transit)/'), "Critical", "HashiCorp Vault"),
    "terraform_state":    (re.compile(r'(?:terraform\.tfstate|\.tfstate|\.tfvars)'), "Critical", "Terraform State"),
    "kubeconfig":         (re.compile(r'(?:kubeconfig|\.kube/config)'), "Critical", "Kubeconfig"),
    "ansible_vault":      (re.compile(r'(?:vault\.yml|vault\.yaml|group_vars/all/vault)'), "High", "Ansible Vault"),
    "npmrc":              (re.compile(r'(?:^|/)\.npmrc'), "High", ".npmrc"),
    "dockerignore":       (re.compile(r'(?:^|/)\.dockerignore'), "Low", ".dockerignore"),
    "gitlab_ci":          (re.compile(r'(?:^|/)\.gitlab-ci\.yml'), "Medium", ".gitlab-ci.yml"),
    "travis":             (re.compile(r'(?:^|/)\.travis\.yml'), "Low", ".travis.yml"),
    "github_workflow":    (re.compile(r'\.github/workflows/'), "Low", "GitHub Workflow"),
    "phpunit":            (re.compile(r'(?:phpunit\.xml|\.phpunit\.result\.cache)'), "Low", "PHPUnit Config"),
    "composer_lock":      (re.compile(r'/composer\.(?:lock|json)'), "Medium", "Composer Manifest"),
    "package_lock":       (re.compile(r'/package-lock\.json|/yarn\.lock|/pnpm-lock\.yaml'), "Low", "Lockfile"),
    "npm_manifest":       (re.compile(r'/package\.json'), "Low", "package.json"),
    "credentials_json":   (re.compile(r'(?:credentials\.json|service-account\.json|gcp-credentials\.json|google-services\.json)'), "Critical", "GCP/Google Credentials"),
    "web_config":         (re.compile(r'/web\.config'), "Medium", "web.config"),
    "crossdomain":        (re.compile(r'/crossdomain\.xml'), "Medium", "crossdomain.xml"),
    "clientaccesspolicy": (re.compile(r'/clientaccesspolicy\.xml'), "Medium", "clientaccesspolicy.xml"),
    "ads_txt":            (re.compile(r'/ads\.txt|/app-ads\.txt'), "Info", "ads.txt"),
    "robots":             (re.compile(r'/robots\.txt'), "Info", "robots.txt"),
    "security_txt":       (re.compile(r'\.well-known/security\.txt'), "Info", "security.txt"),
    "humans_txt":         (re.compile(r'/humans\.txt'), "Info", "humans.txt"),
    "sitemap":            (re.compile(r'/sitemap[^"\s]*\.xml'), "Info", "sitemap.xml"),
    "wellknown":          (re.compile(r'/\.well-known/(?:openid-configuration|oauth-authorization-server|jwks\.json|ai-plugin\.json|assetlinks\.json|apple-app-site-association|gpc\.json|dnt-policy\.txt|trust\.txt|nodeinfo|change-password|webfinger|host-meta)'), "Medium", ".well-known Discovery"),
    "openid":             (re.compile(r'/\.well-known/openid-configuration'), "Medium", "OpenID Configuration"),
    "oauth_server":       (re.compile(r'/\.well-known/oauth-authorization-server'), "Medium", "OAuth Server Metadata"),
    "jwks":               (re.compile(r'/\.well-known/jwks\.json|/jwks\.json'), "Medium", "JWKS Endpoint"),
    "oauth_authorize":    (re.compile(r'/oauth/(?:authorize|token|introspect|revoke|userinfo)'), "Medium", "OAuth Endpoint"),
    "oauth_client_id":    (re.compile(r'client_id=[A-Za-z0-9_\-\.]{10,}'), "Low", "OAuth Client ID"),
    "oauth_client_secret":(re.compile(r'client_secret=[A-Za-z0-9_\-\.]{10,}'), "Critical", "OAuth Client Secret"),
    "jwt_alg_none":       (re.compile(r'"alg"\s*:\s*"none"'), "Critical", "JWT alg=none"),
    "jwt_hs256_weak":     (re.compile(r'"alg"\s*:\s*"HS256"'), "Medium", "JWT HS256"),
    "ldap_injection":     (re.compile(r'\(\s*\|?\s*\(\s*\w+\s*=\s*\*'), "High", "LDAP Injection"),
    "xpath_injection":    (re.compile(r"'\]\s*\|\s*//|\[.*or.*1=1", re.I), "High", "XPath Injection"),
    "xml_bomb":           (re.compile(r'<!ENTITY|<!DOCTYPE[^>]*SYSTEM|<!DOCTYPE[^>]*PUBLIC'), "High", "XXE Payload"),
    "csv_injection":      (re.compile(r'[?&]\w+=(?:%0A|=|\+|-|@|%2b|%2d|%40)(?:cmd|DDE|HYPERLINK|import|call|system)'), "Medium", "CSV Injection"),
    "log4shell":          (re.compile(r'\$\{(?:jndi|lower|upper|env|date|java|sys|ctx|log4j)\:'), "Critical", "Log4Shell Payload"),
    "spring4shell":       (re.compile(r'(?:class\.module\.classLoader|class\.classLoader)'), "Critical", "Spring4Shell Payload"),
    "shellshock":         (re.compile(r'\(\)\s*\{\s*:;\s*\}\s*;'), "Critical", "Shellshock Payload"),

    # ---------- Business-logic ----------
    "order_id":           (re.compile(r'\border_id[=:]["\']?(\d{4,})'), "Medium", "Sequential Order ID"),
    "invoice_id":         (re.compile(r'\binvoice_id[=:]["\']?(\d{4,})'), "Medium", "Sequential Invoice ID"),
    "user_id":            (re.compile(r'\buser_id[=:]["\']?(\d{1,})'), "Medium", "Sequential User ID"),
    "account_id":         (re.compile(r'\baccount_id[=:]["\']?(\d{1,})'), "Medium", "Sequential Account ID"),
    "transaction_id":     (re.compile(r'\b(?:transaction|txn)_id[=:]["\']?(\d{4,})'), "Medium", "Sequential Transaction ID"),
    "session_id":         (re.compile(r'\bsession_id[=:]["\']?([0-9a-zA-Z_\-]{8,})'), "Medium", "Session ID"),
    "session_token":      (re.compile(r'\bsession[_\-]?token[=:]["\']?([A-Za-z0-9_\-\.]{20,})'), "High", "Session Token"),
    "csrf":               (re.compile(r'[?&](?:csrf|_csrf|csrf_token|authenticity_token|_token)=', re.I), "Medium", "CSRF Token in URL"),
    "id_param":           (re.compile(r'[?&](id|uid|pid|sid|tid|fid|gid|nid|rid|mid|aid|bid|cid|did|eid|hid|iid|jid|kid|lid|oid|qid|vid|wid|xid|yid|zid)=\d+', re.I), "Medium", "Numeric ID Parameter"),
    "cors_wildcard":      (re.compile(r'Access-Control-Allow-Origin:\s*\*', re.I), "High", "CORS Wildcard"),
    "cors_reflect":       (re.compile(r'Access-Control-Allow-Origin:\s*\$_(?:GET|REQUEST|COOKIE)', re.I), "High", "CORS Origin Reflection"),
    "cors_credentials":   (re.compile(r'Access-Control-Allow-Credentials:\s*true', re.I), "Medium", "CORS Credentials"),
    "x_frame":            (re.compile(r'X-Frame-Options:\s*(?:ALLOW-FROM|ALLOWALL)', re.I), "Medium", "X-Frame-Options Weak"),
    "csp_unsafe":         (re.compile(r'Content-Security-Policy:[^\n]*unsafe-(?:inline|eval)', re.I), "Medium", "CSP unsafe-inline/eval"),
    "hsts_missing":       (re.compile(r'Strict-Transport-Security', re.I), "Info", "HSTS Present"),
    "set_cookie_no_httponly": (re.compile(r'Set-Cookie:[^\n]*(?<!HttpOnly)(?<!httponly)$', re.M), "Medium", "Cookie without HttpOnly"),
    "set_cookie_no_secure":   (re.compile(r'Set-Cookie:[^\n]*(?<!Secure)(?<!secure)$', re.M), "Medium", "Cookie without Secure"),
    "server_header":      (re.compile(r'Server:\s*([^\r\n]+)', re.I), "Info", "Server Header"),
    "x_powered_by":       (re.compile(r'X-Powered-By:\s*([^\r\n]+)', re.I), "Info", "X-Powered-By Header"),

    # ---------- Subdomain takeover ----------
    "takeover_fingerprint": (re.compile(r'(?:NoSuchBucket|There isn\'t a GitHub Pages site here|Repository not found|Heroku \| No such app|This site is temporarily unavailable|The request could not be satisfied|Fastly error: unknown domain|The specified bucket does not exist|project not found|404 Blog is not found|Do you want to register|The feed has not been found|Sorry, this shop is currently unavailable|Shopify is unavailable|This page is reserved for the domain|The page you were looking for doesn\'t exist|This UserVoice instance doesn\'t exist|Do not have a Tumblr blog|Cargo Collective|Designed by|Please renew your subscription)', re.I), "High", "Subdomain Takeover Fingerprint"),
    "dangling_cname":     (re.compile(r'\b(?:amazonaws\.com|cloudfront\.net|herokuapp\.com|github\.io|githubusercontent\.com|netlify\.app|vercel\.app|surge\.sh|bitbucket\.io|fastly\.net|azurewebsites\.net|cloudapp\.net|trafficmanager\.net|pantheonsite\.io|wordpress\.com|wixsite\.com|webflow\.io|readme\.io|helpscoutdocs\.com|zendesk\.com|statuspage\.io|teamwork\.com|unbouncepages\.com|aftership\.com|campfirehq\.com|desk\.com|feedpress\.me|freshdesk\.com|ghost\.io|hatenablog\.com|helpjuice\.com|helprace\.com|instapage\.com|kajabi\.com|landingi\.com|launchrock\.com|pingdom\.com|proposify\.com|simplebooklet\.com|smartling\.com|smugmug\.com|sophos\.com|strikingly\.com|tave\.com|thinkific\.com|tictail\.com|tumblr\.com|uberflip\.com|uservoice\.com|vend\.com|wpengine\.com|zendesk\.com)\b'), "Medium", "Dangling CNAME Target"),

    # ---------- Info ----------
    "internal_host":      (re.compile(r'\b(?:[a-z0-9\-]+\.)?(?:internal|intranet|corp|staging|stage|dev|test|qa|uat|demo|sandbox|preprod|pre-prod|beta|alpha)\.[a-z0-9\-]+\.[a-z]{2,}\b'), "Medium", "Internal Hostname Leak"),
    "email":              (re.compile(r'\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b'), "Low", "Email Address"),
    "internal_ip":        (re.compile(r'\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b'), "Medium", "Internal IP"),
    "jira_id":            (re.compile(r'\b[A-Z]{2,10}-\d{1,5}\b'), "Low", "Jira/Ticket ID"),
    "aws_arn":            (re.compile(r'\barn:aws:[a-z0-9\-]+:[a-z0-9\-]*:\d{12}:[^\s"\']+'), "Medium", "AWS ARN"),
    "gcp_project":        (re.compile(r'\bprojects/[a-z0-9\-]{6,30}\b'), "Low", "GCP Project"),
    "azure_tenant":       (re.compile(r'\b[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}\b'), "Low", "UUID (tenant / resource)"),
}

# ============================================================
# 4. Parameter classifier
# ============================================================
PARAM_CLASS = {
    "SQLi":   re.compile(r'^(?:id|uid|pid|nid|cat|catid|item|product|page|sel|mode|type|search|query|q|s|keyword|filter|order|sort|by|column|table|field|where|select|report|view|action)$', re.I),
    "XSS":    re.compile(r'^(?:q|s|search|query|keyword|name|title|msg|message|text|comment|content|body|desc|description|callback|jsonp|next|return|returnUrl|return_url|continue|dest|destination|target|redir|redirect_uri|r|u|link|src|source|ref|referrer|from|to|goto|go|out|view|file|path|dir|folder|page|template|lang|locale)$', re.I),
    "SSRF":   re.compile(r'^(?:url|uri|link|src|source|dest|destination|redirect|redirect_uri|return|returnUrl|return_url|next|continue|target|callback|webhook|feed|host|proxy|fetch|load|file|path|resource|reference|ref|image|img|avatar|thumbnail|preview|view|show|open|read|include|require|import|template|layout|page)$', re.I),
    "LFI":    re.compile(r'^(?:file|filename|path|dir|folder|include|inc|require|req|page|template|layout|view|show|doc|document|root|load|read|src|source|url|uri|link|download|upload|attach|attachment|resource|module|mod|config|conf|lang|locale)$', re.I),
    "RCE":    re.compile(r'^(?:cmd|exec|execute|command|run|system|shell|bash|sh|ping|host|ip|domain|target|daemon|process|proc|pid|kill|service|action|op|do|task|job|worker|scheduler|batch|cron|eval|evaluate|assert|debug|test|check|validate|verify)$', re.I),
    "IDOR":   re.compile(r'^(?:id|uid|pid|sid|tid|fid|gid|nid|rid|mid|aid|bid|cid|did|eid|hid|iid|jid|kid|lid|oid|qid|vid|wid|xid|yid|zid|user|user_id|account|account_id|order|order_id|invoice|invoice_id|transaction|transaction_id|report|file|doc|doc_id)$', re.I),
    "REDIR":  re.compile(r'^(?:redirect|redirect_uri|redirect_url|return|returnUrl|return_url|next|nextUrl|next_url|url|uri|link|dest|destination|target|redir|r|u|go|goto|out|view|continue|callback|callbackUrl|callback_url|forward|to)$', re.I),
    "CRLF":   re.compile(r'^(?:url|uri|link|redirect|return|next|callback|path|file|name|host)$', re.I),
    "JWT":    re.compile(r'^(?:token|jwt|access_token|id_token|refresh_token|auth|authorization|bearer)$', re.I),
    "MASS":   re.compile(r'^(?:role|admin|is_admin|user_type|group|permission|access|privilege|status|active|verified|enabled|confirmed|approved)$', re.I),
}

# ============================================================
# 5. Scan
# ============================================================
FINDINGS = defaultdict(lambda: defaultdict(set))  # category -> signature -> {evidence}
URLS, SUBS, IPS, PARAMS = set(), set(), set(), Counter()

for path, text in CORPUS.items():
    # URLs
    for u in re.findall(r'https?://[^\s"\'<>\)\]]+', text):
        u = u.rstrip('.,;:)')
        URLS.add(u)
        try:
            host = urlparse(u).hostname or ""
            if host.endswith(".district.in"): SUBS.add(host)
            for k in parse_qs(urlparse(u).query).keys():
                PARAMS[k] += 1
        except Exception: pass
    # IPs
    for ip in re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', text):
        IPS.add(ip)
    # signatures (per file)
    for sig_name, (pat, sev, label) in SIGS.items():
        for m in pat.finditer(text):
            val = m.group(1) if m.groups() else m.group(0)
            FINDINGS[sig_name]["__sev__"].add(sev)
            FINDINGS[sig_name]["__label__"].add(label)
            FINDINGS[sig_name][path].add(val[:300])

# Entropy-based secret pass (JSON, JS, ENV strings)
ENTROPY_HITS = set()
for path, text in CORPUS.items():
    for tok in re.findall(r'["\']?([A-Za-z0-9+/=_\-\.]{24,})["\']?', text):
        if is_high_entropy(tok, 24, 3.8) and not tok.startswith(("http","www","district","example")):
            if any(c.isdigit() for c in tok) and any(c.isalpha() for c in tok):
                ENTROPY_HITS.add((path, tok))

# Parameter classification
PARAM_FINDINGS = defaultdict(set)
for p in PARAMS:
    for cls, pat in PARAM_CLASS.items():
        if pat.match(p): PARAM_FINDINGS[cls].add(p)

print(f"[*] URLs: {len(URLS)} | Subs: {len(SUBS)} | IPs: {len(IPS)} | Params: {len(PARAMS)}")
print(f"[*] Signature hits: {len([k for k in FINDINGS if k != '__sev__'])}")
print(f"[*] Entropy candidates: {len(ENTROPY_HITS)}")

# ============================================================
# 6. Render HTML
# ============================================================
def esc(x): return html.escape(str(x))

SEV_ORDER = ["Critical","High","Medium","Low","Info"]
SEV_COLOR = {"Critical":"#ff4d4d","High":"#ff8c42","Medium":"#dcdcaa",
             "Low":"#4ec9b0","Info":"#569cd6"}

def render_findings():
    groups = defaultdict(list)   # sev -> [(sig,label,evidence)]
    for sig, files in FINDINGS.items():
        if sig in ("__sev__","__label__"): continue
        sev = next(iter(files.get("__sev__", {"Info"})))
        label = next(iter(files.get("__label__", {sig})))
        evidence = []
        for f, vals in files.items():
            if f in ("__sev__","__label__"): continue
            for v in list(vals)[:5]:
                evidence.append(f"{f}  →  {v}")
        groups[sev].append((sig, label, evidence))

    out = []
    for sev in SEV_ORDER:
        items = groups.get(sev, [])
        if not items: continue
        out.append(f'<h2 style="margin-top:32px">'
                   f'<span class="badge {sev.lower()}">{sev}</span> '
                   f'{len(items)} Finding Categories</h2>')
        for sig, label, evidence in sorted(items, key=lambda x: x[1]):
            ev = "".join(f"<li>{esc(e)}</li>" for e in evidence[:20])
            cnt = len(evidence)
            out.append(f"""
            <div class="section">
              <h3><span class="badge {sev.lower()}">{sev}</span>
              <code>{esc(sig)}</code> — {esc(label)} <small>({cnt} hits)</small></h3>
              <ul>{ev or '<li>—</li>'}</ul>
            </div>""")
    return "".join(out)

def render_params():
    rows = []
    for cls, ps in sorted(PARAM_FINDINGS.items()):
        items = "".join(f"<code>{esc(p)}</code> " for p in sorted(ps))
        rows.append(f"<tr><td><b>{esc(cls)}</b></td><td>{items or '—'}</td></tr>")
    return "".join(rows)

def render_entropy():
    if not ENTROPY_HITS:
        return "<li>No high-entropy tokens detected.</li>"
    seen = set()
    out = []
    for path, tok in sorted(ENTROPY_HITS):
        key = tok[:8]
        if key in seen: continue
        seen.add(key)
        out.append(f"<li><b>{esc(path)}</b> → <code>{esc(tok[:120])}</code> "
                   f"<small>entropy={shannon(tok):.2f}, len={len(tok)}</small></li>")
    return "".join(out[:200])

def render_subs():
    rows = []
    for s in sorted(SUBS):
        risk = ""
        if any(s.startswith(p) for p in ("admin.","accred.","stats.","mesh.",
                                          "queue.","api-","cashless.","cashless-")):
            risk = '<span class="badge high">HIGH</span>'
        if "mailer" in s: risk = '<span class="badge low">MAILER</span>'
        rows.append(f"<li>{esc(s)} {risk}</li>")
    return "".join(rows)

def render_ips():
    return "".join(f"<li>{esc(i)}</li>" for i in sorted(IPS))

# category counts
def cnt(pred):
    return sum(1 for sig in FINDINGS if sig not in ("__sev__","__label__") and pred(sig))

crit = sum(len(v) for k, v in FINDINGS.items()
           if k not in ("__sev__","__label__") and "Critical" in v.get("__sev__", set()))
high = sum(len(v) for k, v in FINDINGS.items()
           if k not in ("__sev__","__label__") and "High" in v.get("__sev__", set()))

HTML = f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<title>Precision Vulnerability Report — district.in</title>
<style>
:root{{--bg:#0b0d11;--card:#161a20;--border:#242a33;--text:#cfd6dd;--accent:#569cd6;
--green:#4ec9b0;--red:#ff5c5c;--orange:#ff8c42;--yellow:#dcdcaa;--muted:#889}}
*{{box-sizing:border-box}}
body{{font-family:ui-sans-serif,system-ui,'Segoe UI',sans-serif;background:var(--bg);
color:var(--text);margin:0;padding:24px;line-height:1.55}}
.container{{max-width:1200px;margin:auto}}
h1{{color:var(--accent);border-bottom:2px solid var(--border);padding-bottom:8px}}
h2{{color:var(--accent);border-bottom:1px solid var(--border);padding-bottom:6px;
font-size:1.15em;margin-top:0}}
h3{{font-size:1em;margin:0 0 6px}}
small{{color:var(--muted);font-weight:normal;font-size:.8em}}
.dashboard{{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));
gap:12px;margin:24px 0}}
.stat-card{{background:var(--card);padding:16px;border-radius:8px;text-align:center;
border-left:4px solid var(--accent)}}
.stat-card h3{{margin:0;font-size:1.6em;color:var(--green);border:none;padding:0}}
.stat-card p{{margin:4px 0 0;font-size:.8em;color:var(--muted)}}
.section{{background:var(--card);padding:16px;border-radius:8px;margin-bottom:14px;
border:1px solid var(--border)}}
ul{{padding-left:20px;font-family:ui-monospace,'Courier New',monospace;font-size:12.5px;
max-height:380px;overflow:auto;margin:6px 0}}
li{{word-break:break-all;border-bottom:1px solid #1f242c;padding:3px 0}}
li:last-child{{border-bottom:none}}
table{{width:100%;border-collapse:collapse;font-size:.9em}}
th,td{{padding:8px;border-bottom:1px solid var(--border);vertical-align:top;text-align:left}}
th{{color:var(--accent)}}
.badge{{display:inline-block;padding:2px 9px;border-radius:10px;font-size:.68em;
font-weight:bold;color:#000;margin-right:6px;text-transform:uppercase}}
.badge.critical{{background:#ff4d4d;color:#fff}}
.badge.high{{background:var(--orange)}}
.badge.medium{{background:var(--yellow)}}
.badge.low{{background:var(--green)}}
.badge.info{{background:var(--accent);color:#fff}}
code{{background:#0a0c10;color:#ce9178;padding:1px 5px;border-radius:3px;font-size:.88em}}
footer{{color:#556;text-align:center;margin-top:40px;font-size:.85em}}
</style></head><body><div class="container">

<h1>🐛 Precision Vulnerability Report — district.in</h1>
<p><small>Content analysis of {len(CORPUS)} files · Shannon-entropy secret detection ·
150+ vuln signatures · {len(URLS)} URLs / {len(SUBS)} subdomains / {len(IPS)} IPs / {len(PARAMS)} params</small></p>

<div class="dashboard">
  <div class="stat-card"><h3>{len(SUBS)}</h3><p>Subdomains</p></div>
  <div class="stat-card"><h3>{len(IPS)}</h3><p>IPs</p></div>
  <div class="stat-card"><h3>{len(URLS)}</h3><p>URLs</p></div>
  <div class="stat-card"><h3>{len(PARAMS)}</h3><p>Parameters</p></div>
  <div class="stat-card"><h3 style="color:#ff4d4d">{crit}</h3><p>Critical Hits</p></div>
  <div class="stat-card"><h3 style="color:#ff8c42">{high}</h3><p>High Hits</p></div>
  <div class="stat-card"><h3>{len(ENTROPY_HITS)}</h3><p>Entropy Candidates</p></div>
</div>

<div class="section">
  <h2>🚨 Findings by Severity</h2>
</div>
{render_findings()}

<div class="section">
  <h2>🔬 Entropy-Based Secret Candidates</h2>
  <p><small>Tokens ≥24 chars with Shannon entropy ≥3.8 and mixed alnum — candidates for manual review.</small></p>
  <ul>{render_entropy()}</ul>
</div>

<div class="section">
  <h2>🎯 Parameters Grouped by Exploit Class</h2>
  <table>
    <tr><th>Class</th><th>Parameters</th></tr>
    {render_params() or '<tr><td colspan=2>—</td></tr>'}
  </table>
</div>

<div class="section">
  <h2>🌐 Subdomains</h2>
  <ul>{render_subs() or '<li>—</li>'}</ul>
</div>

<div class="section">
  <h2>🖥️ IP Addresses</h2>
  <ul>{render_ips() or '<li>—</li>'}</ul>
</div>

<footer>Precision Vulnerability Report · Confidential · Validate each hit before submission.</footer>
</div></body></html>"""

Path(OUT).write_text(HTML, encoding="utf-8")
print(f"[+] Wrote {OUT}")
