# SQLi Evidence Creator — Burp Suite Extension

A Jython-based Burp Suite extension that streamlines SQL injection testing and evidence collection. Define payloads, replay requests with each payload automatically injected, and generate structured plain-text evidence reports — including full redirect chains.

---

## Requirements

- Burp Suite Professional or Community (tested on v2024+)
- Jython Standalone JAR ([download](https://www.jython.org/download))

---

## Installation

1. In Burp Suite, go to **Extender › Options** (or **Settings › Extensions** in newer versions).
2. Under **Python Environment**, set the path to your Jython standalone JAR.
3. Go to **Extender › Extensions › Add**.
4. Set **Extension type** to **Python**.
5. Select `sqli_evidence_creator.py`.
6. Click **Next**. The **"SQLi Evidence Creator"** tab appears in the main Burp UI.

---

## Usage

### Tab 1 — SQL Syntax

Manage your injection payloads.

- Type or paste payloads into the text area, **one per line**.
- **Load from File** — import from a `.txt` file.
- **Save to File** — export the current list.
- **Clear All** — empty the text area.
- A live line counter shows how many payloads are loaded.

```
' OR 1=1--
' UNION SELECT NULL,NULL--
1; WAITFOR DELAY '0:0:5'--
' AND 1=CONVERT(int,(SELECT @@version))--
```

---

### Tab 2 — Auto Repeater

Send the base request once per payload and review all results side by side.

#### Loading a request

1. In Burp's **Proxy**, **Repeater**, **Target**, or any tool, right-click a request.
2. Select **"Send to SQLi Repeater"**.
3. Host, port, and HTTPS are auto-populated. The raw request appears in the left viewer.

#### Target Configuration

| Field | Description |
|---|---|
| **Host / Port / HTTPS** | Auto-filled from the right-clicked request; editable |
| **Parameter=Value** or **Header=Value** | The injection anchor — see below |
| **Injection target** | `Query / Body Parameter` or `HTTP Header` |
| **Inject mode** | `Replace value` or `Retain value + append payload` |

#### Injection target

Choose the location where the payload is injected:

**`Query / Body Parameter`** (default)  
Enter `name=currentvalue`, e.g. `id=1` or `UserId=25` or `username=admin`.  
The extension locates the parameter in this priority order:

| # | Location | Example |
|---|---|---|
| 1 | GET query string | `?id=1` in the URL |
| 2 | POST url-encoded body | `id=1&other=x` |
| 3 | POST JSON body — string value | `"id": "1"` |
| 4 | POST JSON body — numeric/boolean value | `"UserId": 25` |
| 5 | Cookie header pair | `id=1` inside `Cookie:` |
| 6 | Raw fallback | Any `id=1` occurrence |

**`HTTP Header`**  
Enter `HeaderName=currentvalue`, e.g. `User-Agent=Mozilla` or `X-Forwarded-For=127.0.0.1`.  
The extension finds that header and injects into its value.  
For the `Cookie` header, it additionally matches individual cookie pairs.

#### Inject mode

| Mode | Behaviour | Example result |
|---|---|---|
| **Replace value** | Current value is fully replaced | `id=' OR 1=1--` |
| **Retain value + append payload** | Payload is appended after the current value | `id=1' OR 1=1--` |

#### Running payloads

1. Fill in `Parameter=Value` (or `Header=Value`) and choose the target/mode.
2. Click **Send All**.
3. Results populate the table: **#**, **Payload**, **Status Code**, **Response Length**, **Redirects**.
4. Click any row to inspect the modified request and response in the detail viewers.
5. The **Redirects** column shows how many redirect hops were followed for that payload.

#### UI controls

- **Hide / Show Raw Request** — toggles the base request viewer to give more space to the results.

---

### Tab 3 — Report

Generate evidence files for every payload tested.

1. Set the **Evidence folder** path (default: `./evidence`). Use **Browse** to pick a directory.
2. Click **Generate Reports**.
3. The log area shows each file created or any errors.

#### File structure

For each payload result, the extension creates:

```
evidence/
  001_<payload_snippet>.txt               ← original payload request + response
  001_<payload_snippet>_redirect_1.txt    ← redirect hop 1 (if 3xx was returned)
  001_<payload_snippet>_redirect_2.txt    ← redirect hop 2
  002_<payload_snippet>.txt
  ...
```

Up to **10 redirect hops** are followed automatically per payload.

#### File format

```
=== PAYLOAD REQUEST ===

[Full raw HTTP request with injected payload]

============================================================

=== RESPONSE ===

[Full raw HTTP response]
```

Redirect hop files follow the same format with `=== REDIRECT HOP N REQUEST ===` headings.

---

## Architecture

Single file: `sqli_evidence_creator.py`

### Burp interfaces implemented

| Interface | Purpose |
|---|---|
| `IBurpExtender` | Extension entry point |
| `ITab` | Adds the main tab to Burp's UI |
| `IContextMenuFactory` | Right-click "Send to SQLi Repeater" |
| `IMessageEditorController` | Context for Burp's message editor components |

### Key classes

| Class | Purpose |
|---|---|
| `BurpExtender` | All extension logic: UI, injection, redirect following, report generation |
| `ResultsTableModel` | `AbstractTableModel` backing the results `JTable` |
| `_Runnable` | Wraps Python callables as `java.lang.Runnable` for Swing EDT |
| `_SelectionListener` | Wraps a callback as `ListSelectionListener` |
| `_KeyAdapter` | Minimal `KeyListener` for live payload counting |

### Key methods

| Method | Description |
|---|---|
| `_inject_payload` | Injects into query string, POST body (url-encoded + JSON), Cookie, or raw fallback |
| `_inject_payload_in_header` | Injects into a named HTTP request header (any header, including Cookie pairs) |
| `_follow_redirects` | Follows 3xx redirect chains up to `MAX_REDIRECTS` (default 10) |
| `_replace_param_in_json` | Handles both string (`"key": "val"`) and numeric (`"key": 25`) JSON values |

---

## Troubleshooting

**Extension doesn't load**
- Verify the Jython JAR path is set under Extender › Options.
- Check the **Errors** tab in Extender for stack traces.

**"Send to SQLi Repeater" doesn't appear**
- The menu item only shows when right-clicking items that have HTTP messages.

**Parameter not being replaced**
- Make sure the `Parameter=Value` input matches the exact current value in the request (case-sensitive).
- Check Burp's **Output** tab — the extension prints an error if the anchor isn't found.

**Header not being replaced**
- Switch the **Injection target** to `HTTP Header` and enter the exact header name and a value substring that appears in that header, e.g. `User-Agent=Mozilla`.
- The match is case-insensitive on the header name but case-sensitive on the value.

**Reports folder not created**
- Ensure Burp has write permissions to the target directory.
- Use an absolute path if `./evidence` doesn't resolve where expected.

**Redirect files not created**
- Redirect files only appear when the initial response is a 3xx. Confirm the response status in the **Status Code** column.

---

## Disclaimer

This tool is intended for **authorized security testing only**. Only use it against systems you have explicit permission to test. Unauthorized access to computer systems is illegal.

---

## License

MIT
