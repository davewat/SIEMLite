# Security audit

A line-by-line review of SIEMLite v0.14 (every Go package, the embedded web
UI, the Dockerfile, both compose files and the Caddyfile). Each finding below
has a patch in the same commit and a regression check in the security suite,
so a later change can't quietly undo it:

```bash
scripts/security-check.sh
```

The suite is `TestSecurity` in `api/security_test.go`, `pkg/auth/security_test.go`
and `web/security_test.go`; each finding is one named check. To add one, append
to `securityChecks` in the package it belongs to. CI runs the suite on every push.

## What the project is

A single Go binary: an HTTPS API and single-page UI (`api/`, `web/`), a syslog
listener (`pkg/syslogd`), an ingest pipeline into SQLite day files
(`pkg/ingest`, `pkg/storage`), and management of users, access tokens, parsers,
alert rules, backups, updates, email and Microsoft Entra sign-in.

External inputs: the HTTP API (access tokens send logs; users search; admins
manage), the UI's query string and hash, syslog over UDP, TCP and TLS, threat
intel feeds (HTTPS), GeoIP files, Ollama (optional), GitHub releases
(optional), Microsoft login and Graph (optional), SMTP (outbound), uploaded
backups, and the command line.

Every database query uses placeholders; the only `fmt.Sprintf` into SQL carries
integers the program chose. The UI builds the DOM with `textContent` and
element builders and has no `innerHTML`, so log data can't become script.
Passwords are bcrypt; tokens and sessions are 256-bit random and stored as
SHA-256; secrets at rest are AES-GCM with a key kept beside the database and
outside backups; Entra sign-in uses PKCE, state, nonce and RS256 only, checks
issuer, tenant, audience and expiry, and decides membership through Graph, not
the token. Restricted users are filtered in SQL, and alerts and health detail
fail closed for them. The syslog listener has an allowlist, a connection cap,
a frame size cap and idle timeouts. Backup names and archive entries are
matched against fixed patterns before touching the file system.

## Findings

Severity is the impact on a typical deployment: the HTTPS port reachable by the
people who use it, or public behind Caddy.

### 1. Medium: no browser security headers

**Root cause:** no handler set `Content-Security-Policy`, `X-Frame-Options`,
`X-Content-Type-Options`, `Referrer-Policy` or (on the direct HTTPS listener)
`Strict-Transport-Security`. **Attack:** the UI could be framed by another
site, and any future HTML injection in the UI would run script with the
analyst's session; a browser could sniff an API answer as HTML. The
`SameSite=Strict` cookie limits the damage today, which is why this is Medium
and not High.

**Patch:** `api/headers.go` adds the headers to every answer, and
`web.ContentSecurityPolicy()` builds a policy that allows only the page's own
script: the two inline scripts are allowed by SHA-256 hashes computed from the
embedded page, so nothing else can run inline and the policy can't drift from
the page. `frame-ancestors 'none'`, `object-src 'none'`, `base-uri 'none'`.
`Cache-Control: no-store` on every `/api/` answer. The browser test
(`e2e/ui_test.py`) runs the whole UI under the policy and fails on any
console error; one wait in it was rewritten because Playwright evaluated its
predicate with `eval`, which the policy now forbids.

**Checks:** `headers-on-every-answer`, `csp-hashes-every-inline-script`,
`api-answers-are-not-cached`, `hsts-on-https`, and `web`'s `csp-matches-the-page`.

### 2. Medium: the sign-in limiter grew without bound

**Root cause:** `loginLimiter` kept one entry per client address forever
unless that address tried again after its window. **Attack:** failed sign-ins
from ever-changing addresses (an IPv6 /64 gives one host 2^64 of them) grow
the map until the process runs out of memory, before anyone has signed in.

**Patch:** `pkg/auth/users.go` caps the map at 100,000 keys; past that, expired
entries are dropped first, then one at random, so a live lockout survives a
flood (the test checks this).

**Check:** `limiter-memory-is-bounded`.

### 3. Low: failures were only counted per address

**Root cause:** ten failures lock an address out, but an attacker with many
addresses could keep guessing one account's password at ten tries per address.
**Attack:** a password spray from a botnet or a large IPv6 range.

**Patch:** a second limiter counts failures per account (case-insensitive),
from any address, and locks the account for the same 15 minutes after 50
failures: high enough that one colleague's typos can't shut another out, low
enough to slow a spray. Unknown usernames don't count, so the limiter can't be
filled with made-up names.

**Check:** `account-lockout-across-addresses`.

### 4. Low: what was typed as the username reached the server log

**Root cause:** `Login` logged the submitted username on every failure. The
audit log already avoided this (`attemptedUser` in `api/server.go`) because
people sometimes type their password into the username field, but the
`slog` output (and so `docker logs`) didn't. **Attack:** anyone who can read
the container's logs collects passwords.

**Patch:** the server log names the account only when one exists, and says
"(unknown username)" otherwise.

**Check:** `unknown-usernames-stay-out-of-logs`.

### 5. Low: cross-site requests were refused only by `Origin`

**Root cause:** state-changing requests were refused when `Origin` named
another site, but a request with no `Origin` passed. Browsers send `Origin` on
cross-origin writes, so this was defense in depth, with `SameSite=Strict` as
the real guard. **Attack:** none known today; a browser quirk or a future
cookie change would remove the second layer.

**Patch:** `auth.CrossSite` also refuses any request whose `Sec-Fetch-Site`
is `cross-site` or `same-site` (a sibling domain), and the sign-in, sign-out
and `Require` paths all use it. Requests with neither header (tools, old
browsers) are still allowed; they carry no cookie the browser set.

**Check:** `cross-site-requests-refused`.

### 6. Low: embedded folders could be listed

**Root cause:** `http.FileServerFS` lists a folder that has no `index.html`,
so `GET /fonts/` showed the font files. **Attack:** information only; the
folder holds two fonts and their licences.

**Patch:** `web.Handler` answers 404 for any path ending in `/` except `/`.

**Checks:** `no-directory-listing` (api and web).

### 7. Low: generated passwords were slightly biased

**Root cause:** `GeneratePassword` took a random byte modulo 57, so the first
28 characters of the alphabet were each drawn 5/256 of the time and the rest
4/256. **Attack:** a 20-character password still has about 114 bits, so this
was not exploitable, only wrong.

**Patch:** rejection sampling: bytes past the largest multiple of 57 are
redrawn.

**Check:** `generated-passwords-are-uniform`.

## Noted, not patched

These are accepted trade-offs or need a decision beyond a code change.

- **Update integrity (Low).** A self-update verifies the download against
  `SHA256SUMS` fetched from the same GitHub release. That catches corruption,
  not a compromised release. Fixing it means signing releases (for example
  with cosign or minisign) and embedding the public key; a change to the
  release process, not the code alone.
- **First admin password on stdout (Informational).** `bootstrapAdminUser`
  prints it once; in Docker that is in `docker logs` until rotated. The README
  documents it. An alternative is writing it to a 0600 file beside the
  database, as the log generator token already is.
- **Admin-only outbound connections (Informational).** Test email, Entra
  test, intel feeds and the Ollama URL let an admin make the server connect
  to any host. Admins can already read everything, so this isn't an
  escalation; it is noted for anyone running SIEMLite where admins are not
  trusted with the network.
- **Event size (Informational).** A token can store a single 16 MB event.
  The sender is authenticated and retention removes it; a per-field cap
  would be a product decision.
- **Backup upload (Informational).** An admin can upload a gzip bomb that
  fills the disk while it is checked. Admin only; the file is removed when
  the check fails.
