# -*- coding: utf-8 -*-
"""
Burp Suite Extension: SQLi Evidence Creator
Jython-based extension for SQL injection testing and evidence collection.

Tabs:
  1. SQL Syntax   - Manage SQL payloads (one per line)
  2. Auto Repeater - Send requests with each payload injected, view results
  3. Report        - Generate per-payload .txt evidence files (including redirects)
"""

from burp import IBurpExtender, ITab, IContextMenuFactory, IMessageEditorController
from javax.swing import (
    JPanel, JTabbedPane, JTextArea, JScrollPane, JButton, JLabel,
    JTextField, JCheckBox, JTable, JSplitPane, JFileChooser, JMenuItem,
    JOptionPane, SwingUtilities, BorderFactory, BoxLayout, Box,
    JRadioButton, ButtonGroup
)
from javax.swing.table import AbstractTableModel
from javax.swing.event import ListSelectionListener
from java.awt import BorderLayout, FlowLayout, GridBagLayout, GridBagConstraints, Insets, Dimension, Font, Color
from java.awt.event import KeyListener as JKeyListener
from java.lang import Runnable, Short
from java.io import File
from java.net import URL
import re
import os
import io
import threading

# Maximum number of redirects to follow per request
MAX_REDIRECTS = 10


# ---------------------------------------------------------------------------
# Extension entry point
# ---------------------------------------------------------------------------
class BurpExtender(IBurpExtender, ITab, IContextMenuFactory, IMessageEditorController):

    EXTENSION_NAME = "SQLi Evidence Creator"

    # ---- IBurpExtender -----------------------------------------------------
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName(self.EXTENSION_NAME)

        # Shared state
        self._request_bytes = None      # raw request bytes (byte[])
        self._http_service = None       # IHttpService of the sent request
        self._results = []              # list of dicts per payload result

        # Build UI on the Swing EDT
        swing_run(self._build_ui)

        callbacks.registerContextMenuFactory(self)
        callbacks.printOutput("%s loaded successfully." % self.EXTENSION_NAME)

    # ---- ITab --------------------------------------------------------------
    def getTabCaption(self):
        return self.EXTENSION_NAME

    def getUiComponent(self):
        return self._main_tabs

    # ---- IContextMenuFactory -----------------------------------------------
    def createMenuItems(self, invocation):
        menu = JMenuItem("Send to SQLi Repeater")
        menu.addActionListener(lambda e: self._on_send_to_repeater(invocation))
        return [menu]

    # ---- IMessageEditorController ------------------------------------------
    def getHttpService(self):
        return self._http_service

    def getRequest(self):
        return self._request_bytes

    def getResponse(self):
        return None

    # =======================================================================
    # UI CONSTRUCTION
    # =======================================================================
    def _build_ui(self):
        self._main_tabs = JTabbedPane()
        self._main_tabs.addTab("SQL Syntax", self._build_tab_syntax())
        self._main_tabs.addTab("Auto Repeater", self._build_tab_repeater())
        self._main_tabs.addTab("Report", self._build_tab_report())
        self._callbacks.customizeUiComponent(self._main_tabs)
        self._callbacks.addSuiteTab(self)

    # ---- Tab 1: SQL Syntax -------------------------------------------------
    def _build_tab_syntax(self):
        panel = JPanel(BorderLayout(5, 5))
        panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10))

        # Header
        header = JPanel(FlowLayout(FlowLayout.LEFT))
        header.add(JLabel("SQL Payloads (one per line):"))
        self._payload_count_label = JLabel("  Lines: 0")
        self._payload_count_label.setFont(Font("Dialog", Font.BOLD, 12))
        header.add(self._payload_count_label)
        panel.add(header, BorderLayout.NORTH)

        # Text area
        self._payload_area = JTextArea(20, 80)
        self._payload_area.setFont(Font("Monospaced", Font.PLAIN, 13))
        self._payload_area.setLineWrap(False)
        # Update line count on every key release
        self._payload_area.addKeyListener(_KeyAdapter(lambda: self._update_payload_count()))
        panel.add(JScrollPane(self._payload_area), BorderLayout.CENTER)

        # Buttons
        btn_panel = JPanel(FlowLayout(FlowLayout.LEFT, 8, 4))
        btn_load = JButton("Load from File", actionPerformed=lambda e: self._load_payloads())
        btn_save = JButton("Save to File", actionPerformed=lambda e: self._save_payloads())
        btn_clear = JButton("Clear All", actionPerformed=lambda e: self._clear_payloads())
        for b in (btn_load, btn_save, btn_clear):
            btn_panel.add(b)
        panel.add(btn_panel, BorderLayout.SOUTH)

        return panel

    # ---- Tab 2: Auto Repeater ----------------------------------------------
    def _build_tab_repeater(self):
        panel = JPanel(BorderLayout(5, 5))
        panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10))

        # -- Top config row --
        config = JPanel(GridBagLayout())
        config.setBorder(BorderFactory.createTitledBorder("Target Configuration"))
        gbc = GridBagConstraints()
        gbc.insets = Insets(4, 6, 4, 6)
        gbc.anchor = GridBagConstraints.WEST

        self._host_field = JTextField(25)
        self._port_field = JTextField("443", 6)
        self._https_cb = JCheckBox("HTTPS", True)

        # --- param=value / header=value field (shared, label changes with target) ---
        self._param_field = JTextField(30)
        self._param_field_label = JLabel("Parameter=Value:")
        self._hint_label = JLabel("e.g.  id=123  or  UserId=25  or  username=admin")
        self._hint_label.setFont(Font("Dialog", Font.ITALIC, 11))
        self._hint_label.setForeground(Color(120, 120, 120))

        # --- Injection target: Parameter (Query/Body) OR HTTP Header OR Path Segment ---
        self._rb_target_param  = JRadioButton("Query / Body Parameter", True)
        self._rb_target_header = JRadioButton("HTTP Header")
        self._rb_target_path   = JRadioButton("Path Segment")
        target_group = ButtonGroup()
        target_group.add(self._rb_target_param)
        target_group.add(self._rb_target_header)
        target_group.add(self._rb_target_path)

        def _on_target_change(e):
            if self._rb_target_param.isSelected():
                self._param_field_label.setText("Parameter=Value:")
                self._hint_label.setText("e.g.  id=123  or  UserId=25  or  username=admin")
            elif self._rb_target_header.isSelected():
                self._param_field_label.setText("Header=Value:")
                self._hint_label.setText("e.g.  User-Agent=Mozilla  or  id=123  (also injects into matching GET param in the URL)")
            else:
                self._param_field_label.setText("Path Segment:")
                self._hint_label.setText("e.g.  admin  \u2192  GET /admin/userId/ becomes GET /<payload>/userId/  (just enter the segment name, no =value needed)")

        self._rb_target_param.addActionListener(_on_target_change)
        self._rb_target_header.addActionListener(_on_target_change)
        self._rb_target_path.addActionListener(_on_target_change)

        target_panel = JPanel(FlowLayout(FlowLayout.LEFT, 4, 0))
        target_panel.add(JLabel("Injection target:"))
        target_panel.add(self._rb_target_param)
        target_panel.add(self._rb_target_header)
        target_panel.add(self._rb_target_path)

        # --- Inject mode: Replace value / Retain value + append payload ---
        self._rb_replace = JRadioButton("Replace value", True)
        self._rb_retain  = JRadioButton("Retain value + append payload")
        inject_group = ButtonGroup()
        inject_group.add(self._rb_replace)
        inject_group.add(self._rb_retain)
        mode_panel = JPanel(FlowLayout(FlowLayout.LEFT, 4, 0))
        mode_panel.add(JLabel("Inject mode:"))
        mode_panel.add(self._rb_replace)
        mode_panel.add(self._rb_retain)

        # Row 0: Host / Port / HTTPS / Parameter=Value (label changes dynamically)
        gbc.gridy = 0
        gbc.gridx = 0; config.add(JLabel("Host:"), gbc)
        gbc.gridx = 1; config.add(self._host_field, gbc)
        gbc.gridx = 2; config.add(JLabel("Port:"), gbc)
        gbc.gridx = 3; config.add(self._port_field, gbc)
        gbc.gridx = 4; config.add(self._https_cb, gbc)
        gbc.gridx = 5; config.add(self._param_field_label, gbc)
        gbc.gridx = 6; config.add(self._param_field, gbc)

        # Row 1: hint / target selector / inject mode
        gbc.gridy = 1
        gbc.gridx = 0; gbc.gridwidth = 3; config.add(self._hint_label, gbc)
        gbc.gridx = 3; gbc.gridwidth = 2; config.add(target_panel, gbc)
        gbc.gridx = 5; gbc.gridwidth = 2; config.add(mode_panel, gbc)
        gbc.gridwidth = 1

        panel.add(config, BorderLayout.NORTH)

        # -- Centre: button bar + results table + side-by-side viewers --
        centre = JPanel(BorderLayout(5, 5))

        # Raw Request panel (left viewer)
        self._req_panel = JPanel(BorderLayout())
        self._req_panel.setBorder(BorderFactory.createTitledBorder("Raw Request (right-click 'Send to SQLi Repeater')"))
        self._request_viewer = self._callbacks.createMessageEditor(self, False)
        self._req_panel.add(self._request_viewer.getComponent(), BorderLayout.CENTER)

        # Send All button + toggle Raw Request visibility
        btn_bar = JPanel(FlowLayout(FlowLayout.LEFT))
        self._btn_send_all = JButton("Send All", actionPerformed=lambda e: self._send_all())
        self._send_status_label = JLabel("")
        self._btn_toggle_raw = JButton("Hide Raw Request", actionPerformed=lambda e: self._toggle_raw_request())
        btn_bar.add(self._btn_send_all)
        btn_bar.add(self._send_status_label)
        btn_bar.add(Box.createHorizontalStrut(20))
        btn_bar.add(self._btn_toggle_raw)

        # Results table
        self._results_model = ResultsTableModel()
        self._results_table = JTable(self._results_model)
        self._results_table.setAutoResizeMode(JTable.AUTO_RESIZE_ALL_COLUMNS)
        self._results_table.getSelectionModel().addListSelectionListener(
            _SelectionListener(self._on_result_row_selected)
        )
        results_scroll = JScrollPane(self._results_table)
        results_scroll.setPreferredSize(Dimension(0, 200))

        # Detail viewers with titled borders
        self._detail_request_viewer = self._callbacks.createMessageEditor(self, False)
        self._detail_response_viewer = self._callbacks.createMessageEditor(self, False)

        payload_req_panel = JPanel(BorderLayout())
        payload_req_panel.setBorder(BorderFactory.createTitledBorder("Payload Request"))
        payload_req_panel.add(self._detail_request_viewer.getComponent(), BorderLayout.CENTER)

        response_panel = JPanel(BorderLayout())
        response_panel.setBorder(BorderFactory.createTitledBorder("Response"))
        response_panel.add(self._detail_response_viewer.getComponent(), BorderLayout.CENTER)

        # Request and Response details side by side (horizontal)
        detail_split = JSplitPane(
            JSplitPane.HORIZONTAL_SPLIT,
            payload_req_panel,
            response_panel
        )
        detail_split.setResizeWeight(0.5)

        # Raw Request and Payload details side by side (horizontal)
        self._viewers_split = JSplitPane(
            JSplitPane.HORIZONTAL_SPLIT,
            self._req_panel,
            detail_split
        )
        self._viewers_split.setResizeWeight(0.33)

        # Results table (top) and viewers (bottom) in vertical split
        table_viewers_split = JSplitPane(JSplitPane.VERTICAL_SPLIT, results_scroll, self._viewers_split)
        table_viewers_split.setResizeWeight(0.35)

        # Button bar at top, table + viewers in center
        centre.add(btn_bar, BorderLayout.NORTH)
        centre.add(table_viewers_split, BorderLayout.CENTER)
        panel.add(centre, BorderLayout.CENTER)
        return panel

    # ---- Tab 3: Report -----------------------------------------------------
    def _build_tab_report(self):
        panel = JPanel(BorderLayout(5, 5))
        panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10))

        top = JPanel(FlowLayout(FlowLayout.LEFT, 8, 4))
        top.add(JLabel("Evidence folder:"))
        self._evidence_path_field = JTextField("./evidence", 40)
        top.add(self._evidence_path_field)
        btn_browse = JButton("Browse", actionPerformed=lambda e: self._browse_evidence_folder())
        top.add(btn_browse)
        btn_generate = JButton("Generate Reports", actionPerformed=lambda e: self._generate_reports())
        top.add(btn_generate)
        panel.add(top, BorderLayout.NORTH)

        self._report_log = JTextArea(20, 80)
        self._report_log.setEditable(False)
        self._report_log.setFont(Font("Monospaced", Font.PLAIN, 12))
        panel.add(JScrollPane(self._report_log), BorderLayout.CENTER)
        return panel

    # =======================================================================
    # TAB 1 ACTIONS
    # =======================================================================
    def _get_payloads(self):
        """Return non-empty lines from the payload text area."""
        text = self._payload_area.getText()
        if not text:
            return []
        return [l for l in text.split("\n") if l.strip()]

    def _update_payload_count(self):
        count = len(self._get_payloads())
        self._payload_count_label.setText("  Lines: %d" % count)

    def _load_payloads(self):
        chooser = JFileChooser()
        if chooser.showOpenDialog(self._main_tabs) == JFileChooser.APPROVE_OPTION:
            path = chooser.getSelectedFile().getAbsolutePath()
            try:
                with open(path, "r") as f:
                    self._payload_area.setText(f.read())
                self._update_payload_count()
            except Exception as ex:
                JOptionPane.showMessageDialog(self._main_tabs, str(ex), "Error", JOptionPane.ERROR_MESSAGE)

    def _save_payloads(self):
        chooser = JFileChooser()
        if chooser.showSaveDialog(self._main_tabs) == JFileChooser.APPROVE_OPTION:
            path = chooser.getSelectedFile().getAbsolutePath()
            try:
                with io.open(path, "w", encoding="utf-8", errors="replace") as f:
                    f.write(self._payload_area.getText())
            except Exception as ex:
                JOptionPane.showMessageDialog(self._main_tabs, str(ex), "Error", JOptionPane.ERROR_MESSAGE)

    def _clear_payloads(self):
        self._payload_area.setText("")
        self._update_payload_count()

    # =======================================================================
    # CONTEXT MENU – Send to SQLi Repeater
    # =======================================================================
    def _on_send_to_repeater(self, invocation):
        messages = invocation.getSelectedMessages()
        if not messages:
            return
        msg = messages[0]
        service = msg.getHttpService()
        self._http_service = service
        self._request_bytes = msg.getRequest()

        def _update():
            self._host_field.setText(service.getHost())
            self._port_field.setText(str(service.getPort()))
            self._https_cb.setSelected(service.getProtocol() == "https")
            self._request_viewer.setMessage(self._request_bytes, True)
            # Switch to Auto Repeater tab
            self._main_tabs.setSelectedIndex(1)

        SwingUtilities.invokeLater(_Runnable(_update))

    # =======================================================================
    # TAB 2 – TOGGLE RAW REQUEST
    # =======================================================================
    def _toggle_raw_request(self):
        visible = self._req_panel.isVisible()
        self._req_panel.setVisible(not visible)
        if visible:
            self._btn_toggle_raw.setText("Show Raw Request")
        else:
            self._btn_toggle_raw.setText("Hide Raw Request")
        self._viewers_split.resetToPreferredSizes()

    # =======================================================================
    # TAB 2 – SEND ALL
    # =======================================================================
    def _send_all(self):
        payloads = self._get_payloads()
        if not payloads:
            JOptionPane.showMessageDialog(self._main_tabs, "No payloads loaded in the SQL Syntax tab.", "Warning", JOptionPane.WARNING_MESSAGE)
            return
        if self._request_bytes is None:
            JOptionPane.showMessageDialog(self._main_tabs, "No base request loaded.\nRight-click a request and choose 'Send to SQLi Repeater'.", "Warning", JOptionPane.WARNING_MESSAGE)
            return

        param_input = self._param_field.getText().strip()
        if not param_input:
            JOptionPane.showMessageDialog(self._main_tabs, "Please enter the target field.", "Warning", JOptionPane.WARNING_MESSAGE)
            return
        if not self._rb_target_path.isSelected() and "=" not in param_input:
            if self._rb_target_header.isSelected():
                example = "User-Agent=Mozilla  or  X-Forwarded-For=127.0.0.1  or  id=123"
            else:
                example = "id=1  or  UserId=25  or  username=admin"
            JOptionPane.showMessageDialog(
                self._main_tabs,
                "Please enter the target in 'name=value' format.\nExample: %s" % example,
                "Warning",
                JOptionPane.WARNING_MESSAGE
            )
            return

        retain_value = self._rb_retain.isSelected()
        if self._rb_target_header.isSelected():
            inject_target = "header"
        elif self._rb_target_path.isSelected():
            inject_target = "path"
        else:
            inject_target = "param"

        # Disable button while running
        self._btn_send_all.setEnabled(False)
        self._send_status_label.setText("Sending...")

        # Run in background thread to avoid freezing UI
        t = threading.Thread(target=self._send_all_worker, args=(payloads, param_input, retain_value, inject_target))
        t.daemon = True
        t.start()

    def _send_all_worker(self, payloads, param_input, retain_value=False, inject_target="param"):
        results = []
        host = self._host_field.getText().strip()
        try:
            port = int(self._port_field.getText().strip())
        except ValueError:
            port = 443
        use_https = self._https_cb.isSelected()

        base_request = self._helpers.bytesToString(self._request_bytes)

        # Split param_input into name and current value (path mode has no =value)
        if inject_target == "path":
            param_name  = param_input
            param_value = ""
        else:
            eq_idx = param_input.index("=")
            param_name  = param_input[:eq_idx]
            param_value = param_input[eq_idx + 1:]

        for idx, payload in enumerate(payloads):
            try:
                if inject_target == "header":
                    modified = self._inject_payload_in_header(base_request, param_name, param_value, payload, retain_value)
                elif inject_target == "path":
                    modified = self._inject_payload_in_path(base_request, param_name, payload)
                else:
                    modified = self._inject_payload(base_request, param_name, param_value, payload, retain_value)
                mod_bytes = self._helpers.stringToBytes(modified)

                http_service = self._helpers.buildHttpService(host, port, use_https)
                response_obj = self._callbacks.makeHttpRequest(http_service, mod_bytes)

                resp_bytes = response_obj.getResponse()
                status_code = ""
                resp_length = 0
                redirects = []

                if resp_bytes:
                    info = self._helpers.analyzeResponse(resp_bytes)
                    status_code = str(info.getStatusCode())
                    resp_length = len(resp_bytes)

                    # Follow redirects if 3xx
                    if status_code.startswith("3"):
                        redirects = self._follow_redirects(resp_bytes, http_service, host, port, use_https)

                results.append({
                    "index": idx + 1,
                    "payload": payload,
                    "status": status_code,
                    "length": resp_length,
                    "request": mod_bytes,
                    "response": resp_bytes,
                    "redirects": redirects,   # list of {"request": bytes, "response": bytes}
                })
            except Exception as ex:
                results.append({
                    "index": idx + 1,
                    "payload": payload,
                    "status": "ERR",
                    "length": 0,
                    "request": None,
                    "response": None,
                    "redirects": [],
                })
                self._callbacks.printError("Payload #%d error: %s" % (idx + 1, str(ex)))

            # Update status on EDT
            _idx = idx
            _total = len(payloads)
            SwingUtilities.invokeLater(_Runnable(lambda i=_idx, t=_total: self._send_status_label.setText("Sent %d / %d" % (i + 1, t))))

        self._results = results

        def _done():
            self._results_model.setResults(results)
            self._btn_send_all.setEnabled(True)
            self._send_status_label.setText("Done - %d results" % len(results))

        SwingUtilities.invokeLater(_Runnable(_done))

    # =======================================================================
    # REDIRECT FOLLOWING
    # =======================================================================
    def _follow_redirects(self, response_bytes, http_service, host, port, use_https):
        """
        Follow HTTP 3xx redirects up to MAX_REDIRECTS times.
        Returns a list of {'request': bytes, 'response': bytes} for each hop.
        """
        chain = []
        current_response = response_bytes
        current_host = host
        current_port = port
        current_https = use_https

        for _ in range(MAX_REDIRECTS):
            location = self._extract_location_header(current_response)
            if not location:
                break

            # Parse the Location URL – may be absolute or relative
            req_bytes, next_host, next_port, next_https = self._build_redirect_request(
                location, current_host, current_port, current_https
            )
            if req_bytes is None:
                break

            try:
                next_service = self._helpers.buildHttpService(next_host, next_port, next_https)
                resp_obj = self._callbacks.makeHttpRequest(next_service, req_bytes)
                resp_bytes = resp_obj.getResponse()

                chain.append({"request": req_bytes, "response": resp_bytes})

                if resp_bytes:
                    info = self._helpers.analyzeResponse(resp_bytes)
                    status = str(info.getStatusCode())
                    if not status.startswith("3"):
                        break
                    current_response = resp_bytes
                    current_host = next_host
                    current_port = next_port
                    current_https = next_https
                else:
                    break
            except Exception as ex:
                self._callbacks.printError("Redirect follow error: %s" % str(ex))
                break

        return chain

    def _extract_location_header(self, response_bytes):
        """Extract the value of the Location header from a raw HTTP response."""
        try:
            resp_str = self._helpers.bytesToString(response_bytes)
            for line in resp_str.split("\r\n"):
                if line.lower().startswith("location:"):
                    return line[len("location:"):].strip()
        except Exception:
            pass
        return None

    def _build_redirect_request(self, location, current_host, current_port, current_https):
        """
        Build a minimal GET request for the redirect location.
        Returns (request_bytes, host, port, use_https) or (None, ...) on failure.
        """
        try:
            # Absolute URL
            m = re.match(r'^(https?)://([^/:\s]+)(?::(\d+))?(.*)?$', location, re.IGNORECASE)
            if m:
                scheme = m.group(1).lower()
                redir_host = m.group(2)
                redir_port = int(m.group(3)) if m.group(3) else (443 if scheme == "https" else 80)
                redir_path = m.group(4) if m.group(4) else "/"
                redir_https = (scheme == "https")
            else:
                # Relative URL – same host/port/scheme
                redir_host = current_host
                redir_port = current_port
                redir_https = current_https
                redir_path = location if location.startswith("/") else "/" + location

            if not redir_path:
                redir_path = "/"

            raw = "GET %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n" % (redir_path, redir_host)
            req_bytes = self._helpers.stringToBytes(raw)
            return req_bytes, redir_host, redir_port, redir_https
        except Exception as ex:
            self._callbacks.printError("_build_redirect_request error: %s" % str(ex))
            return None, current_host, current_port, current_https

    # =======================================================================
    # HEADER INJECTION
    # =======================================================================
    def _inject_payload_in_header(self, raw_request, header_name, header_value, payload, retain=False):
        """
        Inject payload into a specific HTTP request header identified by
        header_name and its current value (header_value).

        Special handling:
          - Cookie header: injects into cookie pairs (name=value style)
          - All other headers: replaces / appends in the full header value

        retain=False → replace header_value with payload
        retain=True  → keep header_value and append payload after it

        If the header is not found or its value does not match, the request
        is returned unchanged (no silent corruption).
        """
        parts = raw_request.split("\r\n\r\n", 1)
        header_section = parts[0]
        body = parts[1] if len(parts) > 1 else ""

        lines = header_section.split("\r\n")
        new_lines = []
        matched = False

        for line in lines:
            colon_pos = line.find(":")
            if colon_pos <= 0:
                new_lines.append(line)
                continue

            this_name  = line[:colon_pos].strip()
            this_value = line[colon_pos + 1:].strip()

            if this_name.lower() != header_name.lower():
                new_lines.append(line)
                continue

            # ---- Special case: Cookie header (name=value; name2=value2) ----
            if this_name.lower() == "cookie":
                new_cookie = self._replace_param_in_cookie(line, header_value, header_value, payload, retain)
                # For Cookie we treat header_value as both param_name and value anchor:
                # the user enters  CookieName=cookievalue, so we look for "CookieName=cookievalue"
                # _replace_param_in_cookie already does that.  If it doesn't match, fall through
                # and try a raw value replacement inside the cookie string.
                if new_cookie is not None:
                    new_lines.append(new_cookie)
                    matched = True
                    continue
                # Fallback: raw replacement inside the cookie string
                if header_value in this_value:
                    if retain:
                        new_val = this_value.replace(header_value, header_value + payload, 1)
                    else:
                        new_val = this_value.replace(header_value, payload, 1)
                    new_lines.append("%s: %s" % (this_name, new_val))
                    matched = True
                    continue
                new_lines.append(line)
                continue

            # ---- All other headers: match the full value or a substring ----
            if this_value == header_value:
                # Exact match – replace whole value
                injected = (header_value + payload) if retain else payload
                new_lines.append("%s: %s" % (this_name, injected))
                matched = True
            elif header_value in this_value:
                # Substring match (e.g. User-Agent might be long) – replace first occurrence
                if retain:
                    new_val = this_value.replace(header_value, header_value + payload, 1)
                else:
                    new_val = this_value.replace(header_value, payload, 1)
                new_lines.append("%s: %s" % (this_name, new_val))
                matched = True
            else:
                new_lines.append(line)

        if not matched:
            self._callbacks.printError(
                "_inject_payload_in_header: header '%s' with value '%s' not found in request."
                % (header_name, header_value)
            )

        # Also inject into the GET query string if a matching param=value exists there.
        # This covers cases where the same parameter appears in both the URL and a header.
        if header_value and new_lines:
            req_line = new_lines[0]
            m = re.match(r'^(\S+)\s+([^\s\?]+)(\?[^\s]*)?\s+(HTTP/\S+)', req_line)
            if m and m.group(3):
                query = m.group(3)[1:]  # strip leading '?'
                new_query = self._replace_param_in_qs(query, header_name, header_value, payload, retain)
                if new_query is not None:
                    new_lines[0] = "%s %s?%s %s" % (m.group(1), m.group(2), new_query, m.group(4))

        return "\r\n".join(new_lines) + "\r\n\r\n" + body

    # =======================================================================
    # PATH SEGMENT INJECTION
    # =======================================================================
    def _inject_payload_in_path(self, raw_request, segment_name, payload):
        """Inject payload into a named URL path segment.

        e.g. GET /admin/userId/ HTTP/1.1  with  segment_name='admin'
        becomes  GET /<payload>/userId/ HTTP/1.1
        Only the first matching segment is replaced.
        """
        parts = raw_request.split("\r\n\r\n", 1)
        header_section = parts[0]
        body = parts[1] if len(parts) > 1 else ""

        lines = header_section.split("\r\n")
        request_line = lines[0]

        m = re.match(r'^(\S+)\s+(\S+)\s+(HTTP/\S+)', request_line)
        if m:
            method    = m.group(1)
            full_path = m.group(2)
            proto     = m.group(3)

            # Separate path from query string
            path_part  = full_path
            query_part = ""
            if "?" in full_path:
                path_part, query_part = full_path.split("?", 1)
                query_part = "?" + query_part

            # Replace the first matching segment
            segments = path_part.split("/")
            found = False
            new_segments = []
            for seg in segments:
                if not found and seg == segment_name:
                    new_segments.append(payload)
                    found = True
                else:
                    new_segments.append(seg)

            if found:
                new_path = "/".join(new_segments)
                lines[0] = "%s %s%s %s" % (method, new_path, query_part, proto)
                return "\r\n".join(lines) + "\r\n\r\n" + body
            else:
                self._callbacks.printError(
                    "_inject_payload_in_path: segment '%s' not found in path '%s'."
                    % (segment_name, path_part)
                )

        return raw_request

    # =======================================================================
    # PAYLOAD INJECTION  (param=value aware)
    # =======================================================================
    def _inject_payload(self, raw_request, param_name, param_value, payload, retain=False):
        """
        Inject payload into the field identified by param_name=param_value.

        retain=False → replace the current value entirely with payload
        retain=True  → keep the current value and append payload right after it

        Search order:
          1. GET query string
          2. POST url-encoded body
          3. JSON body  (string value: "param": "value"  OR numeric: "param": 25)
          4. Cookie header
          5. Any raw occurrence of param_name=param_value (fallback)
        """
        parts = raw_request.split("\r\n\r\n", 1)
        header_section = parts[0]
        body = parts[1] if len(parts) > 1 else ""

        lines = header_section.split("\r\n")
        request_line = lines[0]

        # ---- 1. GET query string ----
        m = re.match(r'^(\S+)\s+([^\s\?]+)(\?[^\s]*)?\s+(HTTP/\S+)', request_line)
        if m:
            method = m.group(1)
            path = m.group(2)
            query = m.group(3) or ""
            proto = m.group(4)

            if query:
                new_query = self._replace_param_in_qs(query[1:], param_name, param_value, payload, retain)
                if new_query is not None:
                    lines[0] = "%s %s?%s %s" % (method, path, new_query, proto)
                    return "\r\n".join(lines) + "\r\n\r\n" + body

        # ---- 2. POST url-encoded body ----
        if body:
            new_body = self._replace_param_in_qs(body, param_name, param_value, payload, retain)
            if new_body is not None:
                new_header_lines = self._update_content_length(lines, new_body)
                return "\r\n".join(new_header_lines) + "\r\n\r\n" + new_body

        # ---- 3. JSON body (string or numeric value) ----
        if body:
            new_body = self._replace_param_in_json(body, param_name, param_value, payload, retain)
            if new_body is not None:
                new_header_lines = self._update_content_length(lines, new_body)
                return "\r\n".join(new_header_lines) + "\r\n\r\n" + new_body

        # ---- 4. Cookie header ----
        new_header_lines = []
        replaced_in_cookie = False
        for line in lines:
            if line.lower().startswith("cookie:") and not replaced_in_cookie:
                new_line = self._replace_param_in_cookie(line, param_name, param_value, payload, retain)
                if new_line is not None:
                    new_header_lines.append(new_line)
                    replaced_in_cookie = True
                    continue
            new_header_lines.append(line)
        if replaced_in_cookie:
            return "\r\n".join(new_header_lines) + "\r\n\r\n" + body

        # ---- 5. Raw fallback: replace exact param_name=param_value anywhere ----
        if retain:
            replacement = param_value + payload
        else:
            replacement = payload
        replaced, count = re.subn(
            r'(%s=)%s' % (re.escape(param_name), re.escape(param_value)),
            r'\g<1>' + replacement.replace('\\', '\\\\'),
            raw_request
        )
        if count > 0:
            return replaced

        return raw_request

    @staticmethod
    def _update_content_length(header_lines, new_body):
        """Return header_lines with Content-Length updated to match new_body length."""
        updated = []
        found = False
        for line in header_lines:
            if line.lower().startswith("content-length:"):
                updated.append("Content-Length: %d" % len(new_body))
                found = True
            else:
                updated.append(line)
        if not found:
            updated.append("Content-Length: %d" % len(new_body))
        return updated

    @staticmethod
    def _replace_param_in_qs(qs, param_name, param_value, new_value, retain=False):
        """
        Replace param_name=param_value inside a query-string / url-encoded body.
        Only replaces if the current value matches param_value exactly.
        retain=True: keeps param_value and appends new_value.
        Returns modified string or None if not found/matched.
        """
        pairs = qs.split("&")
        found = False
        new_pairs = []
        for pair in pairs:
            if "=" in pair:
                key, val = pair.split("=", 1)
                if key == param_name and val == param_value:
                    injected = (param_value + new_value) if retain else new_value
                    new_pairs.append("%s=%s" % (key, injected))
                    found = True
                else:
                    new_pairs.append(pair)
            else:
                new_pairs.append(pair)
        if found:
            return "&".join(new_pairs)
        return None

    @staticmethod
    def _replace_param_in_json(body, param_name, param_value, new_value, retain=False):
        """
        Replace a JSON value for param_name when it matches param_value.
        Handles both string values ("param": "value") and numeric values ("param": 25).
        retain=True: keeps param_value and appends new_value (result is always a JSON string).
        Returns modified body or None if not found.
        """
        safe_new = new_value.replace('\\', '\\\\')

        # --- String value: "param": "value" ---
        str_pattern = r'("%s"\s*:\s*")%s(")' % (re.escape(param_name), re.escape(param_value))
        if retain:
            str_replacement = r'\g<1>' + param_value + safe_new + r'\g<2>'
        else:
            str_replacement = r'\g<1>' + safe_new + r'\g<2>'
        new_body, count = re.subn(str_pattern, str_replacement, body)
        if count > 0:
            return new_body

        # --- Numeric / boolean / null value: "param": 25  or  "param": true ---
        num_pattern = r'("%s"\s*:\s*)%s(\s*[,}\]\r\n])' % (re.escape(param_name), re.escape(param_value))
        if retain:
            # wrap as a JSON string containing original value + payload
            num_replacement = r'\g<1>"' + param_value + safe_new + r'"\g<2>'
        else:
            # replace number with a JSON string payload
            num_replacement = r'\g<1>"' + safe_new + r'"\g<2>'
        new_body, count = re.subn(num_pattern, num_replacement, body)
        if count > 0:
            return new_body

        return None

    @staticmethod
    def _replace_param_in_cookie(cookie_line, param_name, param_value, new_value, retain=False):
        """
        Replace param_name=param_value inside a Cookie: header line.
        retain=True: keeps param_value and appends new_value.
        Returns modified line or None if not found.
        """
        prefix = cookie_line[:cookie_line.index(":") + 1] + " "
        cookie_str = cookie_line[len(prefix):]
        pairs = cookie_str.split("; ")
        found = False
        new_pairs = []
        for pair in pairs:
            if "=" in pair:
                key, val = pair.split("=", 1)
                if key.strip() == param_name and val == param_value:
                    injected = (param_value + new_value) if retain else new_value
                    new_pairs.append("%s=%s" % (key, injected))
                    found = True
                else:
                    new_pairs.append(pair)
            else:
                new_pairs.append(pair)
        if found:
            return prefix + "; ".join(new_pairs)
        return None

    def _on_result_row_selected(self):
        row = self._results_table.getSelectedRow()
        if row < 0 or row >= len(self._results):
            return
        entry = self._results[row]
        if entry.get("request"):
            self._detail_request_viewer.setMessage(entry["request"], True)
        else:
            self._detail_request_viewer.setMessage(self._helpers.stringToBytes("(no request)"), True)
        if entry.get("response"):
            self._detail_response_viewer.setMessage(entry["response"], False)
        else:
            self._detail_response_viewer.setMessage(self._helpers.stringToBytes("(no response)"), False)

    # =======================================================================
    # TAB 3 – REPORT GENERATION
    # =======================================================================
    def _browse_evidence_folder(self):
        chooser = JFileChooser()
        chooser.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY)
        if chooser.showOpenDialog(self._main_tabs) == JFileChooser.APPROVE_OPTION:
            self._evidence_path_field.setText(chooser.getSelectedFile().getAbsolutePath())

    def _generate_reports(self):
        if not self._results:
            JOptionPane.showMessageDialog(self._main_tabs, "No results to report. Run 'Send All' first.", "Warning", JOptionPane.WARNING_MESSAGE)
            return

        folder = self._evidence_path_field.getText().strip()
        if not folder:
            folder = "./evidence"

        try:
            if not os.path.exists(folder):
                os.makedirs(folder)
        except Exception as ex:
            JOptionPane.showMessageDialog(self._main_tabs, "Cannot create folder: %s" % str(ex), "Error", JOptionPane.ERROR_MESSAGE)
            return

        self._report_log.setText("")
        helpers = self._helpers

        for entry in self._results:
            idx = entry["index"]
            payload = entry["payload"]

            # Build safe filename snippet from payload (first 40 chars, sanitized)
            snippet = re.sub(r'[^a-zA-Z0-9_\-]', '_', payload[:40]).strip('_')
            if not snippet:
                snippet = "payload"
            base_name = "%03d_%s" % (idx, snippet)

            # ---- File 1: Original payload request + response ----
            req_text = self._bytes_to_str(helpers, entry.get("request"))
            resp_text = self._bytes_to_str(helpers, entry.get("response"))

            status_note = ""
            if entry.get("status", "").startswith("3"):
                status_note = "  [3xx – %d redirect(s) followed, see separate files]" % len(entry.get("redirects", []))

            content = (
                req_text + "\n\n" +
                "=" * 60 + "\n\n" +
                resp_text + "\n"
            )

            filepath = os.path.join(folder, base_name + ".txt")
            self._write_file(filepath, content)

            # ---- Files 2..N: Redirect chain ----
            redirects = entry.get("redirects", [])
            for r_idx, hop in enumerate(redirects, start=1):
                hop_req = self._bytes_to_str(helpers, hop.get("request"))
                hop_resp = self._bytes_to_str(helpers, hop.get("response"))

                hop_content = (
                    hop_req + "\n\n" +
                    "=" * 60 + "\n\n" +
                    hop_resp + "\n"
                )
                hop_path = os.path.join(folder, "%s_redirect_%d.txt" % (base_name, r_idx))
                self._write_file(hop_path, hop_content)

        self._report_log.append("\nReport generation complete. %d payloads processed.\n" % len(self._results))

    def _bytes_to_str(self, helpers, data):
        """Safely convert a Java byte array to a Python string."""
        if data is None:
            return "(none)"
        try:
            return helpers.bytesToString(data)
        except Exception:
            return str(data)

    def _write_file(self, filepath, content):
        """Write content to filepath and log the result."""
        try:
            if isinstance(content, bytes):
                content = content.decode("utf-8", errors="replace")
            with io.open(filepath, "w", encoding="utf-8", errors="replace") as f:
                f.write(content)
            self._report_log.append("[+] Created: %s\n" % filepath)
        except Exception as ex:
            self._report_log.append("[-] Failed:  %s – %s\n" % (filepath, str(ex)))


# ===========================================================================
# Table model for results
# ===========================================================================
class ResultsTableModel(AbstractTableModel):
    COLUMNS = ["#", "Payload", "Status Code", "Response Length", "Redirects"]

    def __init__(self):
        self._results = []

    def setResults(self, results):
        self._results = results
        self.fireTableDataChanged()

    def getRowCount(self):
        return len(self._results)

    def getColumnCount(self):
        return len(self.COLUMNS)

    def getColumnName(self, col):
        return self.COLUMNS[col]

    def getValueAt(self, row, col):
        entry = self._results[row]
        if col == 0:
            return entry["index"]
        elif col == 1:
            return entry["payload"]
        elif col == 2:
            return entry["status"]
        elif col == 3:
            return entry["length"]
        elif col == 4:
            return len(entry.get("redirects", []))
        return ""


# ===========================================================================
# Swing helper classes (Jython doesn't support lambda for Java interfaces
# that require specific method names)
# ===========================================================================
class _Runnable(Runnable):
    """Wraps a Python callable as java.lang.Runnable."""
    def __init__(self, fn):
        self._fn = fn
    def run(self):
        self._fn()


class _SelectionListener(ListSelectionListener):
    """Wraps a Python callable as ListSelectionListener."""
    def __init__(self, fn):
        self._fn = fn
    def valueChanged(self, event):
        if not event.getValueIsAdjusting():
            self._fn()


class _KeyAdapter(JKeyListener):
    """Minimal KeyListener that calls fn on keyReleased."""
    def __init__(self, fn):
        self._fn = fn
    def keyReleased(self, event):
        self._fn()
    def keyPressed(self, event):
        pass
    def keyTyped(self, event):
        pass


def swing_run(fn):
    """Execute fn on the Swing EDT and wait for completion."""
    if SwingUtilities.isEventDispatchThread():
        fn()
    else:
        SwingUtilities.invokeAndWait(_Runnable(fn))
