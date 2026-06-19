# -*- coding: utf-8 -*-
"""
Burp Suite Extension: VulnVerificator
Jython-based extension for SQL injection testing and CSRF verification with
file-based evidence collection.

Author : charnyladaro
GitHub : https://github.com/charnyladaro

Tabs:
  1. SQL Syntax        - Manage SQL payloads (one per line)
  2. Auto Repeater     - Send requests with each payload injected, view results
  3. CSRF Verification - Test server-side CSRF token / Referer / Origin validation
  4. Report            - Generate per-payload .txt evidence files (including redirects)
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
from java.awt import BorderLayout, FlowLayout, GridBagLayout, GridBagConstraints, Insets, Dimension, Font, Color, Cursor
from java.awt.event import KeyListener as JKeyListener, MouseAdapter
from java.lang import Runnable, Short
from java.io import File
from java.net import URL, URI
from java.awt import Desktop
from urllib import quote
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

    EXTENSION_NAME = "VulnVerificator"
    AUTHOR         = "charnyladaro"
    GITHUB_URL     = "https://github.com/charnyladaro"

    # ---- IBurpExtender -----------------------------------------------------
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName(self.EXTENSION_NAME)

        # Shared state
        self._request_bytes = None      # raw request bytes (byte[])
        self._http_service = None       # IHttpService of the sent request
        self._results = []              # list of dicts per payload result
        self._csrf_results = None       # dict: CSRF verification outcome

        # Build UI on the Swing EDT
        swing_run(self._build_ui)

        callbacks.registerContextMenuFactory(self)
        callbacks.printOutput("%s loaded successfully." % self.EXTENSION_NAME)
        callbacks.printOutput("Author: %s  -  %s" % (self.AUTHOR, self.GITHUB_URL))

    # ---- ITab --------------------------------------------------------------
    def getTabCaption(self):
        return self.EXTENSION_NAME

    def getUiComponent(self):
        return self._main_tabs

    # ---- IContextMenuFactory -----------------------------------------------
    def createMenuItems(self, invocation):
        item_sqli = JMenuItem("Send to SQLi Repeater")
        item_sqli.addActionListener(lambda e: self._on_send_to_repeater(invocation))
        item_csrf = JMenuItem("Send to CSRF Verification")
        item_csrf.addActionListener(lambda e: self._on_send_to_csrf(invocation))
        return [item_sqli, item_csrf]

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
        self._main_tabs.addTab("CSRF Verification", self._build_tab_csrf())
        self._main_tabs.addTab("Report", self._build_tab_report())
        self._main_tabs.addTab("About", self._build_tab_about())
        self._callbacks.customizeUiComponent(self._main_tabs)
        self._callbacks.addSuiteTab(self)

    # ---- About tab ---------------------------------------------------------
    def _build_tab_about(self):
        panel = JPanel(GridBagLayout())
        panel.setBorder(BorderFactory.createEmptyBorder(20, 20, 20, 20))
        gbc = GridBagConstraints()
        gbc.gridx = 0
        gbc.anchor = GridBagConstraints.WEST
        gbc.insets = Insets(4, 0, 4, 0)

        title = JLabel(self.EXTENSION_NAME)
        title.setFont(Font("Dialog", Font.BOLD, 22))
        gbc.gridy = 0; panel.add(title, gbc)

        subtitle = JLabel("SQL injection testing & CSRF verification with file-based evidence")
        subtitle.setFont(Font("Dialog", Font.PLAIN, 13))
        subtitle.setForeground(Color(90, 90, 90))
        gbc.gridy = 1; panel.add(subtitle, gbc)

        gbc.gridy = 2; panel.add(Box.createVerticalStrut(16), gbc)

        author = JLabel("Author:  %s" % self.AUTHOR)
        author.setFont(Font("Dialog", Font.BOLD, 13))
        gbc.gridy = 3; panel.add(author, gbc)

        # Clickable GitHub link
        link = JLabel("<html><a href=''>%s</a></html>" % self.GITHUB_URL)
        link.setFont(Font("Dialog", Font.PLAIN, 13))
        link.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR))
        link.addMouseListener(_LinkClick(self.GITHUB_URL, self._callbacks))
        gbc.gridy = 4; panel.add(link, gbc)

        gbc.gridy = 5; panel.add(Box.createVerticalStrut(16), gbc)

        note = JLabel("<html><i>For authorized security testing only.</i></html>")
        note.setForeground(Color(120, 120, 120))
        gbc.gridy = 6; panel.add(note, gbc)

        return panel

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

        # URL-encode payload (default on; applied to query/body/cookie/path targets,
        # not to JSON, multipart, or raw header values which are inserted verbatim)
        self._urlencode_cb = JCheckBox("URL-encode payload", True)
        mode_panel.add(Box.createHorizontalStrut(12))
        mode_panel.add(self._urlencode_cb)

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

    def _on_send_to_csrf(self, invocation):
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
            self._csrf_base_viewer.setMessage(self._request_bytes, True)
            # Switch to CSRF Verification tab (index 2)
            self._main_tabs.setSelectedIndex(2)

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

        # Read all Swing fields here on the EDT (never from the worker thread)
        host = self._host_field.getText().strip()
        try:
            port = int(self._port_field.getText().strip())
        except ValueError:
            port = 443
        use_https = self._https_cb.isSelected()
        urlencode = self._urlencode_cb.isSelected()

        # Disable button while running
        self._btn_send_all.setEnabled(False)
        self._send_status_label.setText("Sending...")

        # Run in background thread to avoid freezing UI
        t = threading.Thread(
            target=self._send_all_worker,
            args=(payloads, param_input, retain_value, inject_target, host, port, use_https, urlencode)
        )
        t.daemon = True
        t.start()

    def _send_all_worker(self, payloads, param_input, retain_value=False, inject_target="param",
                         host="", port=443, use_https=True, urlencode=False):
        results = []

        base_request = self._helpers.bytesToString(self._request_bytes)
        carry_headers = self._extract_carry_headers(base_request)

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
                    modified = self._inject_payload_in_path(base_request, param_name, payload, retain_value, urlencode)
                else:
                    modified = self._inject_payload(base_request, param_name, param_value, payload, retain_value, urlencode)
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
                        redirects = self._follow_redirects(resp_bytes, http_service, host, port, use_https, carry_headers)

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
    def _follow_redirects(self, response_bytes, http_service, host, port, use_https, carry_headers=None):
        """
        Follow HTTP 3xx redirects up to MAX_REDIRECTS times.
        Returns a list of {'request': bytes, 'response': bytes} for each hop.
        carry_headers: list of header lines (Cookie/Authorization) to replay so the
        redirect target is fetched with the original session.
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
                location, current_host, current_port, current_https, carry_headers
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

    def _build_redirect_request(self, location, current_host, current_port, current_https, carry_headers=None):
        """
        Build a minimal GET request for the redirect location.
        carry_headers (Cookie/Authorization) are replayed so the session is preserved.
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

            raw = "GET %s HTTP/1.1\r\nHost: %s\r\n" % (redir_path, redir_host)
            if carry_headers:
                raw += "\r\n".join(carry_headers) + "\r\n"
            raw += "Connection: close\r\n\r\n"
            req_bytes = self._helpers.stringToBytes(raw)
            return req_bytes, redir_host, redir_port, redir_https
        except Exception as ex:
            self._callbacks.printError("_build_redirect_request error: %s" % str(ex))
            return None, current_host, current_port, current_https

    @staticmethod
    def _extract_carry_headers(raw_request):
        """Return Cookie/Authorization header lines from a request, to replay across redirects."""
        out = []
        header_section = raw_request.split("\r\n\r\n", 1)[0]
        for line in header_section.split("\r\n")[1:]:
            cpos = line.find(":")
            if cpos > 0 and line[:cpos].strip().lower() in ("cookie", "authorization"):
                out.append(line)
        return out

    @staticmethod
    def _url_encode(s):
        """Percent-encode every reserved character (safe='') so payloads can't break the
        request line / parameter boundaries. Falls back to the raw value on error."""
        try:
            return quote(s, safe='')
        except Exception:
            return s

    # =======================================================================
    # HEADER INJECTION
    # =======================================================================
    def _inject_payload_in_header(self, raw_request, header_name, header_value, payload, retain=False):
        """
        Inject payload into a specific HTTP request header identified by
        header_name and its current value (header_value).

        Replaces (or appends, when retain=True) within the matched header value.
        Header values are inserted verbatim (no URL-encoding).
        To target an individual cookie, use the 'Query / Body Parameter' mode
        instead, which understands cookie name=value pairs.

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

            # ---- Match the full value or a substring ----
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
    def _inject_payload_in_path(self, raw_request, segment_name, payload, retain=False, urlencode=False):
        """Inject payload into a named URL path segment.

        e.g. GET /admin/userId/ HTTP/1.1  with  segment_name='admin'
        retain=False → GET /<payload>/userId/ HTTP/1.1
        retain=True  → GET /admin<payload>/userId/ HTTP/1.1
        Only the first matching segment is replaced. When urlencode is on the
        payload is percent-encoded so spaces / slashes can't break the request line.
        """
        inj = self._url_encode(payload) if urlencode else payload
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
                    new_segments.append(segment_name + inj if retain else inj)
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
    def _inject_payload(self, raw_request, param_name, param_value, payload, retain=False, urlencode=False):
        """
        Inject payload into the field identified by param_name=param_value.

        retain=False → replace the current value entirely with payload
        retain=True  → keep the current value and append payload right after it

        Search order:
          1. GET query string                (URL-encoded when urlencode=True)
          2. Multipart form-data body        (value inserted verbatim)
          3. POST url-encoded body           (URL-encoded when urlencode=True)
          4. JSON body  (string value: "param": "value"  OR numeric: "param": 25)
          5. Cookie header                   (URL-encoded when urlencode=True)
          6. Any raw occurrence of param_name=param_value (fallback)
        """
        parts = raw_request.split("\r\n\r\n", 1)
        header_section = parts[0]
        body = parts[1] if len(parts) > 1 else ""

        lines = header_section.split("\r\n")
        request_line = lines[0]

        # Value used where percent-encoding is appropriate (query / urlencoded body / cookie).
        # JSON and multipart get the raw payload (they have their own escaping / framing).
        enc_payload = self._url_encode(payload) if urlencode else payload

        # ---- 1. GET query string ----
        m = re.match(r'^(\S+)\s+([^\s\?]+)(\?[^\s]*)?\s+(HTTP/\S+)', request_line)
        if m:
            method = m.group(1)
            path = m.group(2)
            query = m.group(3) or ""
            proto = m.group(4)

            if query:
                new_query = self._replace_param_in_qs(query[1:], param_name, param_value, enc_payload, retain)
                if new_query is not None:
                    lines[0] = "%s %s?%s %s" % (method, path, new_query, proto)
                    return "\r\n".join(lines) + "\r\n\r\n" + body

        # ---- 2. Multipart form-data body ----
        if body and self._is_multipart(lines):
            new_body = self._replace_param_in_multipart(header_section, body, param_name, param_value, payload, retain)
            if new_body is not None:
                new_header_lines = self._update_content_length(lines, new_body)
                return "\r\n".join(new_header_lines) + "\r\n\r\n" + new_body

        # ---- 3. POST url-encoded body ----
        if body:
            new_body = self._replace_param_in_qs(body, param_name, param_value, enc_payload, retain)
            if new_body is not None:
                new_header_lines = self._update_content_length(lines, new_body)
                return "\r\n".join(new_header_lines) + "\r\n\r\n" + new_body

        # ---- 4. JSON body (string or numeric value) ----
        if body:
            new_body = self._replace_param_in_json(body, param_name, param_value, payload, retain)
            if new_body is not None:
                new_header_lines = self._update_content_length(lines, new_body)
                return "\r\n".join(new_header_lines) + "\r\n\r\n" + new_body

        # ---- 5. Cookie header ----
        new_header_lines = []
        replaced_in_cookie = False
        for line in lines:
            if line.lower().startswith("cookie:") and not replaced_in_cookie:
                new_line = self._replace_param_in_cookie(line, param_name, param_value, enc_payload, retain)
                if new_line is not None:
                    new_header_lines.append(new_line)
                    replaced_in_cookie = True
                    continue
            new_header_lines.append(line)
        if replaced_in_cookie:
            return "\r\n".join(new_header_lines) + "\r\n\r\n" + body

        # ---- 6. Raw fallback: replace exact param_name=param_value anywhere ----
        replacement = (param_value + enc_payload) if retain else enc_payload
        pattern = r'(%s=)%s' % (re.escape(param_name), re.escape(param_value))
        # Use a function replacement so the payload is never interpreted as a backreference.
        replaced, count = re.subn(pattern, lambda mm: mm.group(1) + replacement, raw_request)
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
        # Escape backslashes and double-quotes so the payload stays valid inside a JSON string.
        safe_new = new_value.replace('\\', '\\\\').replace('"', '\\"')

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

    # =======================================================================
    # MULTIPART / FORM-DATA HELPERS  (shared by injection and CSRF)
    # =======================================================================
    @staticmethod
    def _is_multipart(header_lines):
        """True if a Content-Type: multipart/form-data header is present."""
        for line in header_lines:
            if line.lower().startswith("content-type:") and "multipart/form-data" in line.lower():
                return True
        return False

    @staticmethod
    def _get_multipart_boundary(header_section, body):
        """Return the multipart boundary string (the value after 'boundary=', i.e. WITHOUT
        the leading '--' that prefixes it in the body). None if it can't be determined."""
        for line in header_section.split("\r\n"):
            if line.lower().startswith("content-type:") and "multipart/form-data" in line.lower():
                m = re.search(r'boundary=("?)([^";\r\n]+)\1', line, re.IGNORECASE)
                if m:
                    return m.group(2).strip()
        # Fallback: derive from the first body line (which is '--' + boundary)
        first = body.split("\r\n", 1)[0]
        if first.startswith("--"):
            return first[2:].rstrip()
        return None

    def _replace_param_in_multipart(self, header_section, body, param_name, param_value, new_value, retain=False):
        """Replace the value of a multipart form-data field named param_name, but only when
        its current value equals param_value. retain=True appends new_value. The value is
        inserted verbatim (multipart parts are not URL-encoded).
        Returns the modified body, or None if the field/value was not found."""
        boundary = self._get_multipart_boundary(header_section, body)
        if not boundary:
            return None
        delim = "--" + boundary
        segments = body.split(delim)
        found = False
        out = []
        for seg in segments:
            name_m = re.search(r'name="([^"]*)"', seg)
            if name_m and name_m.group(1) == param_name:
                hb = seg.split("\r\n\r\n", 1)
                if len(hb) == 2:
                    headers_part, valpart = hb
                    if valpart.endswith("\r\n"):
                        value, trail = valpart[:-2], "\r\n"
                    else:
                        value, trail = valpart, ""
                    if value == param_value:
                        injected = (param_value + new_value) if retain else new_value
                        out.append(headers_part + "\r\n\r\n" + injected + trail)
                        found = True
                        continue
            out.append(seg)
        if found:
            return delim.join(out)
        return None

    def _multipart_modify(self, body, boundary, name, mode):
        """Empty ('empty') or delete ('delete') a multipart field by name, regardless of its
        current value. Returns (new_body, found). Used by CSRF token neutralization."""
        delim = "--" + boundary
        segments = body.split(delim)
        found = False
        out = []
        for seg in segments:
            name_m = re.search(r'name="([^"]*)"', seg)
            if name_m and name_m.group(1) == name:
                found = True
                if mode == "delete":
                    # Drop the whole part (and its leading delimiter).
                    continue
                hb = seg.split("\r\n\r\n", 1)
                if len(hb) == 2:
                    headers_part = hb[0]
                    trail = "\r\n" if hb[1].endswith("\r\n") else ""
                    out.append(headers_part + "\r\n\r\n" + trail)
                    continue
            out.append(seg)
        if found:
            return delim.join(out), True
        return body, False

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
        if not self._results and not self._csrf_results:
            JOptionPane.showMessageDialog(self._main_tabs, "No results to report. Run 'Send All' or a CSRF test first.", "Warning", JOptionPane.WARNING_MESSAGE)
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

        if self._csrf_results:
            self._write_csrf_evidence(folder, helpers)

        self._report_log.append("\nReport generation complete. %d payloads processed.\n" % len(self._results))

    # =======================================================================
    # TAB 3 (CSRF) – UI
    # =======================================================================
    def _build_tab_csrf(self):
        panel = JPanel(BorderLayout(5, 5))
        panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10))

        # ---- Config ----
        config = JPanel(GridBagLayout())
        config.setBorder(BorderFactory.createTitledBorder("CSRF Test Configuration"))
        gbc = GridBagConstraints()
        gbc.insets = Insets(4, 6, 4, 6)
        gbc.anchor = GridBagConstraints.WEST

        self._csrf_token_name = JTextField(20)
        self._csrf_no_token_cb = JCheckBox("Request has no token (test Referer/Origin instead)")
        self._csrf_reject_codes = JTextField("400, 403", 10)
        self._csrf_error_regex = JTextField(24)
        self._csrf_follow_redirects_cb = JCheckBox("Follow redirects", True)

        # Token location radios
        self._csrf_loc_auto      = JRadioButton("Auto", True)
        self._csrf_loc_param     = JRadioButton("Query/Body param")
        self._csrf_loc_json      = JRadioButton("JSON field")
        self._csrf_loc_multipart = JRadioButton("Multipart field")
        self._csrf_loc_header    = JRadioButton("Header")
        self._csrf_loc_cookie    = JRadioButton("Cookie")
        loc_group = ButtonGroup()
        for rb in (self._csrf_loc_auto, self._csrf_loc_param, self._csrf_loc_json,
                   self._csrf_loc_multipart, self._csrf_loc_header, self._csrf_loc_cookie):
            loc_group.add(rb)
        loc_panel = JPanel(FlowLayout(FlowLayout.LEFT, 4, 0))
        loc_panel.add(self._csrf_loc_auto)
        loc_panel.add(self._csrf_loc_param)
        loc_panel.add(self._csrf_loc_json)
        loc_panel.add(self._csrf_loc_multipart)
        loc_panel.add(self._csrf_loc_header)
        loc_panel.add(self._csrf_loc_cookie)

        hint = JLabel("Token name e.g.  csrf_token  /  authenticity_token  /  X-CSRF-Token")
        hint.setFont(Font("Dialog", Font.ITALIC, 11))
        hint.setForeground(Color(120, 120, 120))

        # Row 0
        gbc.gridy = 0
        gbc.gridx = 0; config.add(JLabel("Token name:"), gbc)
        gbc.gridx = 1; config.add(self._csrf_token_name, gbc)
        gbc.gridx = 2; gbc.gridwidth = 2; config.add(self._csrf_no_token_cb, gbc); gbc.gridwidth = 1
        # Row 1
        gbc.gridy = 1
        gbc.gridx = 0; gbc.gridwidth = 4; config.add(hint, gbc); gbc.gridwidth = 1
        # Row 2
        gbc.gridy = 2
        gbc.gridx = 0; config.add(JLabel("Token location:"), gbc)
        gbc.gridx = 1; gbc.gridwidth = 3; config.add(loc_panel, gbc); gbc.gridwidth = 1
        # Row 3
        gbc.gridy = 3
        gbc.gridx = 0; config.add(JLabel("Reject status codes:"), gbc)
        gbc.gridx = 1; config.add(self._csrf_reject_codes, gbc)
        gbc.gridx = 2; config.add(JLabel("Error-page regex:"), gbc)
        gbc.gridx = 3; config.add(self._csrf_error_regex, gbc)
        # Row 4
        gbc.gridy = 4
        gbc.gridx = 0; config.add(self._csrf_follow_redirects_cb, gbc)
        samesite = JLabel("Note: tests server-side token/Referer/Origin validation only - not browser SameSite.")
        samesite.setFont(Font("Dialog", Font.ITALIC, 11))
        samesite.setForeground(Color(120, 120, 120))
        gbc.gridx = 1; gbc.gridwidth = 3; config.add(samesite, gbc); gbc.gridwidth = 1

        panel.add(config, BorderLayout.NORTH)

        # ---- Centre: button bar + verdict + table + viewers ----
        centre = JPanel(BorderLayout(5, 5))

        btn_bar = JPanel(FlowLayout(FlowLayout.LEFT))
        self._btn_csrf_run = JButton("Run CSRF Test", actionPerformed=lambda e: self._run_csrf_test())
        self._csrf_status_label = JLabel("")
        self._csrf_verdict_label = JLabel(" ")
        self._csrf_verdict_label.setFont(Font("Dialog", Font.BOLD, 14))
        btn_bar.add(self._btn_csrf_run)
        btn_bar.add(self._csrf_status_label)
        btn_bar.add(Box.createHorizontalStrut(20))
        btn_bar.add(JLabel("Verdict:"))
        btn_bar.add(self._csrf_verdict_label)

        self._csrf_model = CsrfResultsTableModel()
        self._csrf_table = JTable(self._csrf_model)
        self._csrf_table.setAutoResizeMode(JTable.AUTO_RESIZE_ALL_COLUMNS)
        self._csrf_table.getSelectionModel().addListSelectionListener(
            _SelectionListener(self._on_csrf_row_selected)
        )
        csrf_scroll = JScrollPane(self._csrf_table)
        csrf_scroll.setPreferredSize(Dimension(0, 160))

        # Base request viewer (left) + test request/response (right)
        self._csrf_base_viewer = self._callbacks.createMessageEditor(self, False)
        self._csrf_req_viewer = self._callbacks.createMessageEditor(self, False)
        self._csrf_resp_viewer = self._callbacks.createMessageEditor(self, False)

        base_panel = JPanel(BorderLayout())
        base_panel.setBorder(BorderFactory.createTitledBorder("Loaded Base Request (right-click -> 'Send to CSRF Verification')"))
        base_panel.add(self._csrf_base_viewer.getComponent(), BorderLayout.CENTER)

        test_req_panel = JPanel(BorderLayout())
        test_req_panel.setBorder(BorderFactory.createTitledBorder("Test Request"))
        test_req_panel.add(self._csrf_req_viewer.getComponent(), BorderLayout.CENTER)

        test_resp_panel = JPanel(BorderLayout())
        test_resp_panel.setBorder(BorderFactory.createTitledBorder("Response"))
        test_resp_panel.add(self._csrf_resp_viewer.getComponent(), BorderLayout.CENTER)

        detail_split = JSplitPane(JSplitPane.HORIZONTAL_SPLIT, test_req_panel, test_resp_panel)
        detail_split.setResizeWeight(0.5)
        viewers_split = JSplitPane(JSplitPane.HORIZONTAL_SPLIT, base_panel, detail_split)
        viewers_split.setResizeWeight(0.33)
        table_viewers = JSplitPane(JSplitPane.VERTICAL_SPLIT, csrf_scroll, viewers_split)
        table_viewers.setResizeWeight(0.35)

        centre.add(btn_bar, BorderLayout.NORTH)
        centre.add(table_viewers, BorderLayout.CENTER)
        panel.add(centre, BorderLayout.CENTER)
        return panel

    def _csrf_location(self):
        if self._csrf_loc_param.isSelected():
            return "param"
        if self._csrf_loc_json.isSelected():
            return "json"
        if self._csrf_loc_multipart.isSelected():
            return "multipart"
        if self._csrf_loc_header.isSelected():
            return "header"
        if self._csrf_loc_cookie.isSelected():
            return "cookie"
        return "auto"

    def _on_csrf_row_selected(self):
        if not self._csrf_results:
            return
        row = self._csrf_table.getSelectedRow()
        tests = self._csrf_results.get("tests", [])
        if row < 0 or row >= len(tests):
            return
        entry = tests[row]
        if entry.get("request"):
            self._csrf_req_viewer.setMessage(entry["request"], True)
        else:
            self._csrf_req_viewer.setMessage(self._helpers.stringToBytes("(no request - token not found)"), True)
        if entry.get("response"):
            self._csrf_resp_viewer.setMessage(entry["response"], False)
        else:
            self._csrf_resp_viewer.setMessage(self._helpers.stringToBytes("(no response)"), False)

    # =======================================================================
    # TAB 3 (CSRF) – RUN
    # =======================================================================
    def _run_csrf_test(self):
        if self._request_bytes is None:
            JOptionPane.showMessageDialog(self._main_tabs, "No base request loaded.\nRight-click a request and choose 'Send to CSRF Verification'.", "Warning", JOptionPane.WARNING_MESSAGE)
            return

        no_token = self._csrf_no_token_cb.isSelected()
        token_name = self._csrf_token_name.getText().strip()
        if not no_token and not token_name:
            JOptionPane.showMessageDialog(self._main_tabs, "Enter the CSRF token name, or tick 'Request has no token'.", "Warning", JOptionPane.WARNING_MESSAGE)
            return

        reject_codes = set()
        for tok in self._csrf_reject_codes.getText().split(","):
            tok = tok.strip()
            if tok.isdigit():
                reject_codes.add(int(tok))
        if not reject_codes:
            reject_codes = set([400, 403])

        error_regex = None
        rgx = self._csrf_error_regex.getText().strip()
        if rgx:
            try:
                error_regex = re.compile(rgx, re.IGNORECASE)
            except Exception as ex:
                JOptionPane.showMessageDialog(self._main_tabs, "Invalid error-page regex: %s" % str(ex), "Error", JOptionPane.ERROR_MESSAGE)
                return

        host = self._host_field.getText().strip()
        if not host:
            JOptionPane.showMessageDialog(self._main_tabs, "Host is empty. Load a request first.", "Warning", JOptionPane.WARNING_MESSAGE)
            return
        try:
            port = int(self._port_field.getText().strip())
        except ValueError:
            port = 443
        use_https = self._https_cb.isSelected()
        location = self._csrf_location()
        follow = self._csrf_follow_redirects_cb.isSelected()

        self._btn_csrf_run.setEnabled(False)
        self._csrf_status_label.setText("Running...")
        self._csrf_verdict_label.setText(" ")

        t = threading.Thread(
            target=self._run_csrf_test_worker,
            args=(token_name, no_token, location, reject_codes, error_regex, follow, host, port, use_https)
        )
        t.daemon = True
        t.start()

    def _run_csrf_test_worker(self, token_name, no_token, location, reject_codes, error_regex, follow, host, port, use_https):
        helpers = self._helpers
        service = helpers.buildHttpService(host, port, use_https)
        base_raw = helpers.bytesToString(self._request_bytes)
        carry_headers = self._extract_carry_headers(base_raw)
        tests = []

        # ---- Baseline: original request ----
        base_resp = self._send_raw(service, self._request_bytes)
        baseline = self._summarize(base_resp, follow, service, host, port, use_https, carry_headers)
        tests.append({
            "name": "Baseline (original request)",
            "request": self._request_bytes,
            "response": baseline["final_response"],
            "status": baseline["status"],
            "length": baseline["length"],
            "result": "BASELINE",
            "reason": "reference success response",
        })

        if no_token:
            # ---- Branch 2: Referer / Origin ----
            branch = "Referer / Origin"
            header_tests = [
                ("Referer removed", ["Referer"]),
                ("Origin removed", ["Origin"]),
                ("Referer + Origin removed", ["Referer", "Origin"]),
            ]
            for label, hdrs in header_tests:
                mod = base_raw
                for h in hdrs:
                    mod = self._remove_header(mod, h)
                mod_bytes = helpers.stringToBytes(mod)
                resp = self._send_raw(service, mod_bytes)
                summ = self._summarize(resp, follow, service, host, port, use_https, carry_headers)
                result, reason = self._classify(summ, baseline, reject_codes, error_regex)
                tests.append({
                    "name": label, "request": mod_bytes, "response": summ["final_response"],
                    "status": summ["status"], "length": summ["length"],
                    "result": result, "reason": reason,
                })
            both = [t for t in tests if t["name"] == "Referer + Origin removed"]
            if both and both[0]["result"] == "ACCEPTED":
                verdict = "CSRF POSITIVE - accepted with no token and no Referer/Origin"
                color = "red"
            elif both and both[0]["result"] == "ERROR":
                verdict = "INCONCLUSIVE - request error, see results"
                color = "orange"
            else:
                verdict = "PROTECTED - removing Referer/Origin was rejected"
                color = "green"
        else:
            # ---- Branch 1: CSRF token ----
            branch = "CSRF token"
            mod_e, found_e = self._csrf_neutralize_token(base_raw, token_name, location, "empty")
            mod_d, found_d = self._csrf_neutralize_token(base_raw, token_name, location, "delete")
            variants = [
                ("Token value emptied", mod_e, found_e),
                ("Token param deleted", mod_d, found_d),
            ]
            for label, mod, found in variants:
                if not found:
                    tests.append({
                        "name": label, "request": None, "response": None,
                        "status": "-", "length": 0, "result": "NOT FOUND",
                        "reason": "token '%s' not located in %s" % (token_name, location),
                    })
                    continue
                mod_bytes = helpers.stringToBytes(mod)
                resp = self._send_raw(service, mod_bytes)
                summ = self._summarize(resp, follow, service, host, port, use_https, carry_headers)
                result, reason = self._classify(summ, baseline, reject_codes, error_regex)
                tests.append({
                    "name": label, "request": mod_bytes, "response": summ["final_response"],
                    "status": summ["status"], "length": summ["length"],
                    "result": result, "reason": reason,
                })
            accepted = [t for t in tests if t["result"] == "ACCEPTED"
                        and t["name"] in ("Token value emptied", "Token param deleted")]
            if not (found_e or found_d):
                verdict = "INCONCLUSIVE - token '%s' not found (check name/location)" % token_name
                color = "orange"
            elif accepted:
                verdict = "VULNERABLE - action accepted without a valid CSRF token"
                color = "red"
            else:
                verdict = "PROTECTED - token removal was rejected"
                color = "green"

        self._csrf_results = {"verdict": verdict, "branch": branch, "tests": tests, "color": color}

        def _done():
            self._csrf_model.setTests(tests)
            self._btn_csrf_run.setEnabled(True)
            self._csrf_status_label.setText("Done - %d tests" % len(tests))
            self._csrf_verdict_label.setText(verdict)
            if color == "red":
                self._csrf_verdict_label.setForeground(Color(0xB0, 0x00, 0x00))
            elif color == "green":
                self._csrf_verdict_label.setForeground(Color(0x00, 0x80, 0x00))
            else:
                self._csrf_verdict_label.setForeground(Color(0xC0, 0x60, 0x00))

        SwingUtilities.invokeLater(_Runnable(_done))

    # =======================================================================
    # CSRF – HTTP + classification helpers
    # =======================================================================
    def _send_raw(self, service, req_bytes):
        try:
            obj = self._callbacks.makeHttpRequest(service, req_bytes)
            return obj.getResponse()
        except Exception as ex:
            self._callbacks.printError("CSRF send error: %s" % str(ex))
            return None

    def _summarize(self, resp_bytes, follow, service, host, port, use_https, carry_headers=None):
        """Return final status/length/response after optionally following redirects."""
        final = resp_bytes
        status = -1
        length = 0
        if resp_bytes:
            info = self._helpers.analyzeResponse(resp_bytes)
            status = int(info.getStatusCode())
            length = len(resp_bytes)
            if follow and 300 <= status < 400:
                chain = self._follow_redirects(resp_bytes, service, host, port, use_https, carry_headers)
                if chain:
                    last = chain[-1].get("response")
                    if last:
                        final = last
                        info2 = self._helpers.analyzeResponse(last)
                        status = int(info2.getStatusCode())
                        length = len(last)
        return {"final_response": final, "status": status, "length": length}

    def _classify(self, summ, baseline, reject_codes, error_regex):
        """Return (result, reason). result in ACCEPTED / REJECTED / INCONCLUSIVE / ERROR."""
        resp = summ["final_response"]
        if resp is None:
            return ("ERROR", "no response received")
        status = summ["status"]
        if status in reject_codes:
            return ("REJECTED", "status %d in reject list" % status)
        body = self._helpers.bytesToString(resp)
        if error_regex is not None and error_regex.search(body):
            return ("REJECTED", "error-page pattern matched")
        if status == 200 or status == baseline["status"]:
            return ("ACCEPTED", "status %d matches success baseline" % status)
        return ("INCONCLUSIVE", "status %d differs from baseline %s, no error match"
                % (status, baseline["status"]))

    # =======================================================================
    # CSRF – request mutation helpers
    # =======================================================================
    def _remove_header(self, raw_request, header_name):
        """Return raw_request with all lines of header_name removed (request line kept)."""
        parts = raw_request.split("\r\n\r\n", 1)
        header_section = parts[0]
        body = parts[1] if len(parts) > 1 else ""
        lines = header_section.split("\r\n")
        out = [lines[0]]
        for line in lines[1:]:
            cpos = line.find(":")
            if cpos > 0 and line[:cpos].strip().lower() == header_name.lower():
                continue
            out.append(line)
        return "\r\n".join(out) + "\r\n\r\n" + body

    def _csrf_neutralize_token(self, raw_request, name, location, mode):
        """Empty ('empty') or delete ('delete') the named token. Returns (modified, found)."""
        if location == "param":
            order = ["query", "body", "multipart", "cookie"]
        elif location == "json":
            order = ["json"]
        elif location == "multipart":
            order = ["multipart"]
        elif location == "header":
            order = ["header"]
        elif location == "cookie":
            order = ["cookie"]
        else:
            order = ["query", "body", "multipart", "json", "cookie", "header"]
        for loc in order:
            new, found = self._neutralize_in(raw_request, name, mode, loc)
            if found:
                return new, True
        return raw_request, False

    def _neutralize_in(self, raw, name, mode, loc):
        if loc == "query":
            return self._neut_query(raw, name, mode)
        if loc == "body":
            return self._neut_body(raw, name, mode)
        if loc == "multipart":
            return self._neut_multipart(raw, name, mode)
        if loc == "json":
            return self._neut_json(raw, name, mode)
        if loc == "cookie":
            return self._neut_cookie(raw, name, mode)
        if loc == "header":
            return self._neut_header(raw, name, mode)
        return raw, False

    @staticmethod
    def _qs_modify(qs, name, mode):
        """Empty or delete name in an &-separated key=value string. Returns (new, found)."""
        pairs = qs.split("&")
        out = []
        found = False
        for p in pairs:
            if "=" in p:
                k, _v = p.split("=", 1)
                if k == name:
                    found = True
                    if mode == "empty":
                        out.append("%s=" % k)
                    continue
            elif p == name:
                found = True
                if mode == "empty":
                    out.append("%s=" % p)
                continue
            out.append(p)
        return "&".join(out), found

    def _neut_query(self, raw, name, mode):
        parts = raw.split("\r\n\r\n", 1)
        header_section = parts[0]
        body = parts[1] if len(parts) > 1 else ""
        lines = header_section.split("\r\n")
        m = re.match(r'^(\S+)\s+([^\s\?]+)(\?[^\s]*)?\s+(HTTP/\S+)', lines[0])
        if m and m.group(3):
            new_qs, found = self._qs_modify(m.group(3)[1:], name, mode)
            if found:
                if new_qs:
                    lines[0] = "%s %s?%s %s" % (m.group(1), m.group(2), new_qs, m.group(4))
                else:
                    lines[0] = "%s %s %s" % (m.group(1), m.group(2), m.group(4))
                return "\r\n".join(lines) + "\r\n\r\n" + body, True
        return raw, False

    def _neut_body(self, raw, name, mode):
        parts = raw.split("\r\n\r\n", 1)
        header_section = parts[0]
        body = parts[1] if len(parts) > 1 else ""
        if not body:
            return raw, False
        new_body, found = self._qs_modify(body, name, mode)
        if found:
            lines = self._update_content_length(header_section.split("\r\n"), new_body)
            return "\r\n".join(lines) + "\r\n\r\n" + new_body, True
        return raw, False

    def _neut_multipart(self, raw, name, mode):
        parts = raw.split("\r\n\r\n", 1)
        header_section = parts[0]
        body = parts[1] if len(parts) > 1 else ""
        if not body:
            return raw, False
        boundary = self._get_multipart_boundary(header_section, body)
        if not boundary:
            return raw, False
        new_body, found = self._multipart_modify(body, boundary, name, mode)
        if found:
            lines = self._update_content_length(header_section.split("\r\n"), new_body)
            return "\r\n".join(lines) + "\r\n\r\n" + new_body, True
        return raw, False

    def _neut_json(self, raw, name, mode):
        parts = raw.split("\r\n\r\n", 1)
        header_section = parts[0]
        body = parts[1] if len(parts) > 1 else ""
        if not body:
            return raw, False
        new_body, found = self._json_modify(body, name, mode)
        if found:
            lines = self._update_content_length(header_section.split("\r\n"), new_body)
            return "\r\n".join(lines) + "\r\n\r\n" + new_body, True
        return raw, False

    @staticmethod
    def _json_modify(body, name, mode):
        """Empty or delete a JSON key. Returns (new_body, found)."""
        key = re.escape(name)
        val = r'(?:"(?:[^"\\]|\\.)*"|true|false|null|-?\d+(?:\.\d+)?)'
        if mode == "empty":
            pat = r'("%s"\s*:\s*)%s' % (key, val)
            new_body, c = re.subn(pat, r'\g<1>""', body, count=1)
            return new_body, c > 0
        # delete: try to also remove an adjacent comma to keep JSON well-formed
        for pat in (r',\s*"%s"\s*:\s*%s' % (key, val),
                    r'"%s"\s*:\s*%s\s*,' % (key, val),
                    r'"%s"\s*:\s*%s' % (key, val)):
            new_body, c = re.subn(pat, '', body, count=1)
            if c > 0:
                return new_body, True
        return body, False

    def _neut_cookie(self, raw, name, mode):
        parts = raw.split("\r\n\r\n", 1)
        header_section = parts[0]
        body = parts[1] if len(parts) > 1 else ""
        lines = header_section.split("\r\n")
        out = []
        found = False
        for line in lines:
            if (not found) and line.lower().startswith("cookie:"):
                prefix = line[:line.index(":") + 1] + " "
                cookie_str = line[len(prefix):]
                new_pairs = []
                hit = False
                for pair in cookie_str.split("; "):
                    if "=" in pair:
                        k, _v = pair.split("=", 1)
                        if k.strip() == name:
                            hit = True
                            if mode == "empty":
                                new_pairs.append("%s=" % k)
                            continue
                    new_pairs.append(pair)
                if hit:
                    found = True
                    if new_pairs:
                        out.append(prefix + "; ".join(new_pairs))
                    # if no cookies left, drop the header entirely
                    continue
            out.append(line)
        if found:
            return "\r\n".join(out) + "\r\n\r\n" + body, True
        return raw, False

    def _neut_header(self, raw, name, mode):
        parts = raw.split("\r\n\r\n", 1)
        header_section = parts[0]
        body = parts[1] if len(parts) > 1 else ""
        lines = header_section.split("\r\n")
        out = [lines[0]]
        found = False
        for line in lines[1:]:
            cpos = line.find(":")
            if cpos > 0 and line[:cpos].strip().lower() == name.lower():
                found = True
                if mode == "empty":
                    out.append("%s:" % line[:cpos])
                continue
            out.append(line)
        if found:
            return "\r\n".join(out) + "\r\n\r\n" + body, True
        return raw, False

    # =======================================================================
    # CSRF – evidence
    # =======================================================================
    def _write_csrf_evidence(self, folder, helpers):
        if not self._csrf_results:
            return
        res = self._csrf_results
        summary = []
        summary.append("CSRF VERIFICATION REPORT")
        summary.append("=" * 60)
        summary.append("Overall verdict : %s" % res["verdict"])
        summary.append("Branch tested   : %s" % res["branch"])
        summary.append("")
        summary.append("%-30s %-8s %-9s %-12s %s" % ("Test", "Status", "Length", "Result", "Reason"))
        summary.append("-" * 90)
        for t in res["tests"]:
            summary.append("%-30s %-8s %-9s %-12s %s"
                           % (t["name"], t["status"], t["length"], t["result"], t["reason"]))
        self._write_file(os.path.join(folder, "csrf_summary.txt"), "\n".join(summary) + "\n")

        for i, t in enumerate(res["tests"]):
            snippet = re.sub(r'[^a-zA-Z0-9_\-]', '_', t["name"][:40]).strip('_') or "test"
            base_name = "csrf_%02d_%s" % (i, snippet)
            req_text = self._bytes_to_str(helpers, t.get("request"))
            resp_text = self._bytes_to_str(helpers, t.get("response"))
            content = req_text + "\n\n" + "=" * 60 + "\n\n" + resp_text + "\n"
            self._write_file(os.path.join(folder, base_name + ".txt"), content)

        self._report_log.append("\nCSRF evidence written (%d files + summary).\n" % len(res["tests"]))

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


class CsrfResultsTableModel(AbstractTableModel):
    COLUMNS = ["Test", "Status", "Length", "Result", "Reason"]

    def __init__(self):
        self._tests = []

    def setTests(self, tests):
        self._tests = tests
        self.fireTableDataChanged()

    def getRowCount(self):
        return len(self._tests)

    def getColumnCount(self):
        return len(self.COLUMNS)

    def getColumnName(self, col):
        return self.COLUMNS[col]

    def getValueAt(self, row, col):
        t = self._tests[row]
        if col == 0:
            return t["name"]
        elif col == 1:
            return t["status"]
        elif col == 2:
            return t["length"]
        elif col == 3:
            return t["result"]
        elif col == 4:
            return t["reason"]
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


class _LinkClick(MouseAdapter):
    """Opens a URL in the system browser when the component is clicked."""
    def __init__(self, url, callbacks=None):
        self._url = url
        self._callbacks = callbacks
    def mouseClicked(self, event):
        try:
            if Desktop.isDesktopSupported():
                Desktop.getDesktop().browse(URI(self._url))
        except Exception as ex:
            if self._callbacks:
                self._callbacks.printError("Open URL failed: %s" % str(ex))


def swing_run(fn):
    """Execute fn on the Swing EDT and wait for completion."""
    if SwingUtilities.isEventDispatchThread():
        fn()
    else:
        try:
            SwingUtilities.invokeAndWait(_Runnable(fn))
        except Exception:
            # Don't let an EDT hiccup abort extension load; fall back to async.
            SwingUtilities.invokeLater(_Runnable(fn))
