# SQLi Evidence Creator — Burp Suite Extension

A Jython-based Burp Suite extension that streamlines SQL injection testing and evidence collection. Define payloads, replay requests with each payload injected into a target parameter, and auto-generate plain-text evidence reports.

## Requirements

- Burp Suite Professional or Community (tested on v2024+)
- Jython Standalone JAR ([download](https://www.jython.org/download))

## Installation

1. In Burp Suite, go to **Extender > Options** (or **Settings > Extensions** in newer versions).
2. Under **Python Environment**, set the path to your Jython standalone JAR file.
3. Go to **Extender > Extensions > Add**.
4. Set **Extension type** to **Python**.
5. Select the file: `sqli_evidence_creator.py`
6. Click **Next**. The **"SQLi Evidence Creator"** tab will appear in the main Burp UI.

## Usage

### Tab 1 — SQL Syntax

Manage your SQL injection payloads.

- Type or paste payloads into the text area, **one per line**.
- **Load from File** — import payloads from a `.txt` file.
- **Save to File** — export the current payload list.
- **Clear All** — empty the text area.
- A live line counter shows how many payloads are loaded.

Example payloads:

```
' OR 1=1--
' UNION SELECT NULL,NULL--
1; WAITFOR DELAY '0:0:5'--
' AND 1=CONVERT(int,(SELECT @@version))--
```

### Tab 2 — Auto Repeater

Send the base request once per payload and review the results.

**Loading a request:**

1. In Burp's **Proxy**, **Repeater**, **Target**, or any other tool, right-click a request.
2. Select **"Send to SQLi Repeater"** from the context menu.
3. The request and target details (host, port, HTTPS) are auto-populated.

**Running payloads:**

1. Enter the **Parameter** name whose value should be replaced with each payload (e.g. `id`, `username`, `q`).
2. Click **"Send All"**.
3. The extension iterates through every payload, injects it into the specified parameter, sends the request, and collects the response.
4. Results appear in the table with columns: **#**, **Payload**, **Status Code**, **Response Length**.
5. Click any row to inspect the full modified request and response in the detail viewers below.

**Supported parameter locations:**

- GET query string parameters (`/path?param=value`)
- POST url-encoded body parameters (`param=value&other=123`)

### Tab 3 — Report

Generate evidence files for documentation or reporting.

1. Set the **Evidence folder** path (defaults to `./evidence`). Use **Browse** to pick a directory.
2. Click **"Generate Reports"**.
3. One `.txt` file is created per payload result, named `001_payload_snippet.txt`, `002_payload_snippet.txt`, etc.
4. The status log shows each file as it is created.

**File format:**

```
[Full raw HTTP request with injected payload]
========================================
[Full raw HTTP response]
```

## Architecture

Single file: `sqli_evidence_creator.py`

**Burp interfaces implemented:**

| Interface | Purpose |
|---|---|
| `IBurpExtender` | Extension entry point |
| `ITab` | Adds the main tab to Burp's UI |
| `IContextMenuFactory` | Adds the right-click "Send to SQLi Repeater" menu item |
| `IMessageEditorController` | Provides context for Burp's message editor components |

**Key classes:**

| Class | Purpose |
|---|---|
| `BurpExtender` | Main extension logic, UI construction, request sending, report generation |
| `ResultsTableModel` | `AbstractTableModel` backing the results JTable |
| `_Runnable` | Wraps Python callables as `java.lang.Runnable` for Swing EDT |
| `_SelectionListener` | Wraps a callback as `ListSelectionListener` |
| `_KeyAdapter` | Minimal `KeyListener` for live payload counting |

## Troubleshooting

**Extension doesn't load:**
- Verify the Jython JAR path is set correctly under Extender > Options.
- Check the **Errors** tab in Extender for stack traces.

**"Send to SQLi Repeater" doesn't appear:**
- The menu item only appears when right-clicking on requests (items with HTTP messages), not on empty areas.

**Parameter not being replaced:**
- Ensure the parameter name matches exactly (case-sensitive).
- The extension supports url-encoded GET and POST parameters. JSON or multipart body parameters are not supported.

**Reports folder not created:**
- Ensure Burp has write permissions to the specified directory.
- Use an absolute path if the relative `./evidence` default doesn't resolve where expected.

## Disclaimer

This tool is intended for **authorized security testing only**. Only use it against systems you have explicit permission to test. Unauthorized access to computer systems is illegal.

## License

MIT
