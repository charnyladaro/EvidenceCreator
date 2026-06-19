# VulnVerificator

A [Burp Suite](https://portswigger.net/burp) extension (Jython) for **SQL injection testing** and **CSRF verification** that automates payload injection across a request and generates clean, per-payload `.txt` evidence files — including the full redirect chain.

Built for bug-bounty and pentest workflows where you need reproducible, file-based proof for every payload you send.

**Author:** [charnyladaro](https://github.com/charnyladaro)
**GitHub:** https://github.com/charnyladaro

---

## Features

- **Bulk payload injection** — load a list of SQL payloads (one per line) and fire them against a single request in one click.
- **Flexible injection targets**
  - Query / Body parameter (auto-detects: query string → multipart → url-encoded body → JSON → cookie)
  - HTTP header
  - URL path segment
- **Two injection modes** — *Replace value* or *Retain value + append payload*.
- **Multipart `form-data` aware** — injects into multipart fields verbatim and detects fields by name (e.g. Struts `org.apache.struts.taglib.html.TOKEN`).
- **Optional URL-encoding** — encodes payloads for query/body/cookie/path targets so payloads with spaces or reserved characters can't corrupt the request line.
- **Automatic redirect following** — follows up to 10 `3xx` hops, replaying `Cookie`/`Authorization` so the redirect target is captured with the original session.
- **CSRF Verification tab** — tests server-side anti-CSRF protection by neutralizing the token (empty / delete) or stripping `Referer`/`Origin`, then classifies the result with a clear verdict.
- **Evidence reports** — generates a `.txt` file per payload (request + response), separate files for each redirect hop, and a CSRF summary table.

---

## Requirements

- **Burp Suite** (Community or Professional)
- **Jython standalone 2.7.x** JAR — required to run Python extensions in Burp

---

## Installation

1. **Install Jython in Burp** (one-time):
   - Download the [Jython standalone 2.7.x JAR](https://www.jython.org/download).
   - In Burp: **Extensions → Extensions settings → Python environment** → set the location of the Jython JAR.

2. **Load the extension:**
   - Burp: **Extensions → Installed → Add**
   - **Extension type:** Python
   - **Extension file:** select `vuln_verificator.py`
   - Click **Next**. You should see `VulnVerificator loaded successfully.` in the output, and a new **VulnVerificator** tab.

---

## Usage

### 1. SQL Syntax tab
Paste or load your payloads — one per line. Use **Load from File** / **Save to File** / **Clear All** to manage the list. The line counter shows how many payloads are queued.

### 2. Auto Repeater tab
1. In Burp's **Proxy** or **Repeater**, right-click the target request → **Send to SQLi Repeater**.
   The host, port, and HTTPS flag are populated automatically and the raw request is shown.
2. Configure the injection:
   - **Injection target:** Query/Body Parameter, HTTP Header, or Path Segment
   - **Field:** enter `name=value` for the parameter/header you want to inject (for Path Segment, just the segment name)
   - **Inject mode:** *Replace value* or *Retain value + append payload*
   - **URL-encode payload:** on by default (recommended for query/path)
3. Click **Send All**. Each payload is injected and sent; results populate the table with status code, response length, and redirect count.
4. Select any row to view the **Payload Request** and **Response** side by side.

> The field must currently match what's in the request. If `id=123` isn't found with that exact value, the request is left unchanged rather than silently corrupted — adjust the `name=value` to match the live request.

### 3. CSRF Verification tab
1. Right-click a state-changing request → **Send to CSRF Verification**.
2. Configure the test:
   - **Token name** — e.g. `csrf_token`, `authenticity_token`, `org.apache.struts.taglib.html.TOKEN`
   - **Token location** — Auto, Query/Body param, JSON field, **Multipart field**, Header, or Cookie
   - Or tick **Request has no token** to test `Referer`/`Origin` validation instead
   - **Reject status codes** (default `400, 403`) and an optional **error-page regex** to detect soft rejections
3. Click **Run CSRF Test**. The extension sends a baseline, then the neutralized variants, and shows a colored **verdict**:
   - 🔴 **VULNERABLE / CSRF POSITIVE** — action accepted without a valid token (or with `Referer`/`Origin` removed)
   - 🟢 **PROTECTED** — token/header removal was rejected
   - 🟠 **INCONCLUSIVE / NOT FOUND** — token couldn't be located, or the response was ambiguous

> This tests **server-side** token / `Referer` / `Origin` validation only — it does not assess browser `SameSite` cookie behavior.

### 4. Report tab
1. Set the **Evidence folder** (defaults to `./evidence`) or **Browse** to one.
2. Click **Generate Reports**. For each payload you get:
   - `NNN_<payload-snippet>.txt` — the injected request and its response
   - `NNN_<payload-snippet>_redirect_N.txt` — one file per followed redirect hop
   - `csrf_summary.txt` + per-test files when a CSRF test has been run

### 5. About tab
Shows the app name, author, and a clickable link to the GitHub profile.

---

## How injection targets are resolved

| Target | Search order / behavior |
|--------|--------------------------|
| **Query / Body Parameter** | query string → multipart field → url-encoded body → JSON value (string or numeric) → cookie → raw fallback |
| **HTTP Header** | matched header value (exact or substring); also injects a matching query param of the same name |
| **Path Segment** | first path segment matching the given name |

URL-encoding applies to query, url-encoded body, cookie, and path targets. JSON and multipart values are inserted verbatim (with JSON quote/backslash escaping).

---

## Notes & limitations

- Injection only fires when the specified `name=value` actually matches the live request — this is intentional to avoid corrupting requests.
- Redirect following is capped at **10 hops** and replays `Cookie`/`Authorization` headers only.
- CSRF classification treats a `200` (or a status matching the success baseline) as *accepted*; use the **error-page regex** field to catch soft-error pages that return `200`.
- `Content-Length` is recalculated automatically when the body is modified.

---

## ⚠️ Legal & ethical use

This tool is for **authorized security testing only** — bug-bounty programs within scope, engagements you have written permission for, or systems you own. Unauthorized testing against systems you do not have permission to assess is illegal. You are solely responsible for how you use it.

---

## Author

**charnyladaro** — https://github.com/charnyladaro

## License

No license specified yet. Add one (e.g. MIT) if you intend others to reuse this.
