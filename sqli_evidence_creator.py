# -*- coding: utf-8 -*-
"""
Burp Suite Extension: SQLi Evidence Creator
Jython-based extension for SQL injection testing and evidence collection.

Tabs:
  1. SQL Syntax   - Manage SQL payloads (one per line)
  2. Auto Repeater - Send requests with each payload injected, view results
  3. Report        - Generate per-payload .txt evidence files
"""

from burp import IBurpExtender, ITab, IContextMenuFactory, IMessageEditorController
from javax.swing import (
    JPanel, JTabbedPane, JTextArea, JScrollPane, JButton, JLabel,
    JTextField, JCheckBox, JTable, JSplitPane, JFileChooser, JMenuItem,
    JOptionPane, SwingUtilities, BorderFactory, BoxLayout, Box
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
import threading


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
        self._param_field = JTextField(20)

        labels = ["Host:", "Port:", "", "Parameter:"]
        widgets = [self._host_field, self._port_field, self._https_cb, self._param_field]
        for i, (lbl, wid) in enumerate(zip(labels, widgets)):
            gbc.gridx = i * 2
            gbc.gridy = 0
            if lbl:
                config.add(JLabel(lbl), gbc)
            gbc.gridx = i * 2 + 1
            config.add(wid, gbc)

        panel.add(config, BorderLayout.NORTH)

        # -- Centre: request viewer + send button + results table + detail --
        centre = JPanel(BorderLayout(5, 5))

        # Request viewer
        req_panel = JPanel(BorderLayout())
        req_panel.setBorder(BorderFactory.createTitledBorder("Raw Request (right-click 'Send to SQLi Repeater')"))
        self._request_viewer = self._callbacks.createMessageEditor(self, False)
        req_panel.add(self._request_viewer.getComponent(), BorderLayout.CENTER)

        # Send All button
        btn_bar = JPanel(FlowLayout(FlowLayout.LEFT))
        self._btn_send_all = JButton("Send All", actionPerformed=lambda e: self._send_all())
        self._send_status_label = JLabel("")
        btn_bar.add(self._btn_send_all)
        btn_bar.add(self._send_status_label)
        req_panel.add(btn_bar, BorderLayout.SOUTH)

        # Results table
        self._results_model = ResultsTableModel()
        self._results_table = JTable(self._results_model)
        self._results_table.setAutoResizeMode(JTable.AUTO_RESIZE_ALL_COLUMNS)
        self._results_table.getSelectionModel().addListSelectionListener(
            _SelectionListener(self._on_result_row_selected)
        )
        results_scroll = JScrollPane(self._results_table)
        results_scroll.setPreferredSize(Dimension(0, 200))

        # Detail viewers (request + response side-by-side)
        self._detail_request_viewer = self._callbacks.createMessageEditor(self, False)
        self._detail_response_viewer = self._callbacks.createMessageEditor(self, False)
        detail_split = JSplitPane(
            JSplitPane.HORIZONTAL_SPLIT,
            self._detail_request_viewer.getComponent(),
            self._detail_response_viewer.getComponent()
        )
        detail_split.setResizeWeight(0.5)

        # Combine results table + detail into a vertical split
        bottom_split = JSplitPane(JSplitPane.VERTICAL_SPLIT, results_scroll, detail_split)
        bottom_split.setResizeWeight(0.4)

        # Combine request viewer (top) and bottom section
        top_bottom = JSplitPane(JSplitPane.VERTICAL_SPLIT, req_panel, bottom_split)
        top_bottom.setResizeWeight(0.3)

        centre.add(top_bottom, BorderLayout.CENTER)
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
                with open(path, "w") as f:
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
        param_name = self._param_field.getText().strip()
        if not param_name:
            JOptionPane.showMessageDialog(self._main_tabs, "Please enter a parameter name.", "Warning", JOptionPane.WARNING_MESSAGE)
            return

        # Disable button while running
        self._btn_send_all.setEnabled(False)
        self._send_status_label.setText("Sending...")

        # Run in background thread to avoid freezing UI
        t = threading.Thread(target=self._send_all_worker, args=(payloads, param_name))
        t.daemon = True
        t.start()

    def _send_all_worker(self, payloads, param_name):
        results = []
        host = self._host_field.getText().strip()
        try:
            port = int(self._port_field.getText().strip())
        except ValueError:
            port = 443
        use_https = self._https_cb.isSelected()

        base_request = self._helpers.bytesToString(self._request_bytes)

        for idx, payload in enumerate(payloads):
            try:
                modified = self._inject_payload(base_request, param_name, payload)
                mod_bytes = self._helpers.stringToBytes(modified)

                http_service = self._helpers.buildHttpService(host, port, use_https)
                response_obj = self._callbacks.makeHttpRequest(http_service, mod_bytes)

                resp_bytes = response_obj.getResponse()
                status_code = ""
                resp_length = 0
                if resp_bytes:
                    info = self._helpers.analyzeResponse(resp_bytes)
                    status_code = str(info.getStatusCode())
                    resp_length = len(resp_bytes)

                results.append({
                    "index": idx + 1,
                    "payload": payload,
                    "status": status_code,
                    "length": resp_length,
                    "request": mod_bytes,
                    "response": resp_bytes,
                })
            except Exception as ex:
                results.append({
                    "index": idx + 1,
                    "payload": payload,
                    "status": "ERR",
                    "length": 0,
                    "request": None,
                    "response": None,
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

    def _inject_payload(self, raw_request, param_name, payload):
        """Replace param_name's value in GET query string or POST url-encoded body."""
        # Split headers and body
        parts = raw_request.split("\r\n\r\n", 1)
        header_section = parts[0]
        body = parts[1] if len(parts) > 1 else ""

        lines = header_section.split("\r\n")
        request_line = lines[0]  # e.g. GET /path?a=1&b=2 HTTP/1.1

        # Try to replace in query string (GET parameters)
        match = re.match(r'^(\S+)\s+([^\s\?]+)(\?[^\s]*)?\s+(HTTP/\S+)', request_line)
        if match:
            method = match.group(1)
            path = match.group(2)
            query = match.group(3) or ""
            proto = match.group(4)

            if query:
                new_query = self._replace_param_in_qs(query[1:], param_name, payload)
                if new_query is not None:
                    lines[0] = "%s %s?%s %s" % (method, path, new_query, proto)
                    return "\r\n".join(lines) + "\r\n\r\n" + body

        # Try to replace in POST body (url-encoded)
        if body:
            new_body = self._replace_param_in_qs(body, param_name, payload)
            if new_body is not None:
                # Update Content-Length
                new_header_lines = []
                cl_updated = False
                for line in lines:
                    if line.lower().startswith("content-length:"):
                        new_header_lines.append("Content-Length: %d" % len(new_body))
                        cl_updated = True
                    else:
                        new_header_lines.append(line)
                if not cl_updated:
                    new_header_lines.append("Content-Length: %d" % len(new_body))
                return "\r\n".join(new_header_lines) + "\r\n\r\n" + new_body

        # Fallback: direct text replacement of param=<value>
        pattern = r'(%s=)([^&\s]*)' % re.escape(param_name)
        replaced, count = re.subn(pattern, r'\g<1>' + payload.replace('\\', '\\\\'), raw_request)
        if count > 0:
            return replaced

        return raw_request

    @staticmethod
    def _replace_param_in_qs(qs, param_name, new_value):
        """Replace a parameter value inside a query-string / url-encoded body.
        Returns the modified string, or None if param not found."""
        pairs = qs.split("&")
        found = False
        new_pairs = []
        for pair in pairs:
            if "=" in pair:
                key, _ = pair.split("=", 1)
                if key == param_name:
                    new_pairs.append("%s=%s" % (key, new_value))
                    found = True
                else:
                    new_pairs.append(pair)
            else:
                new_pairs.append(pair)
        if found:
            return "&".join(new_pairs)
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
            filename = "%03d_%s.txt" % (idx, snippet)
            filepath = os.path.join(folder, filename)

            req_text = ""
            if entry.get("request"):
                req_text = helpers.bytesToString(entry["request"])
            resp_text = ""
            if entry.get("response"):
                resp_text = helpers.bytesToString(entry["response"])

            content = "%s\n%s\n%s\n" % (req_text, "=" * 40, resp_text)

            try:
                with open(filepath, "w") as f:
                    f.write(content)
                self._report_log.append("[+] Created: %s\n" % filepath)
            except Exception as ex:
                self._report_log.append("[-] Failed: %s - %s\n" % (filepath, str(ex)))

        self._report_log.append("\nReport generation complete. %d files.\n" % len(self._results))


# ===========================================================================
# Table model for results
# ===========================================================================
class ResultsTableModel(AbstractTableModel):
    COLUMNS = ["#", "Payload", "Status Code", "Response Length"]

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
