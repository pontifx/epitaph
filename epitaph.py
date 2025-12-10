# Epitaph Burp Extension (Jython)
# Tracks host-level testing goals with color-coded progress and JSON export.
# Load in Burp Suite via Extender -> Add -> Extension type: Python.

from burp import IBurpExtender, ITab, IHttpListener, IExtensionStateListener
from java.awt import BorderLayout, Color, Dimension
from java.lang import Runnable, System
from javax.swing import (BoxLayout, JButton, JCheckBox, JLabel, JPanel, JScrollPane,
                         JSplitPane, JTable, JTextArea, JTextField, ListSelectionModel,
                         SwingUtilities, JProgressBar, JOptionPane)
from javax.swing.event import ListSelectionListener
from javax.swing.table import AbstractTableModel, DefaultTableCellRenderer, TableCellRenderer
from java.awt.event import ItemListener, ItemEvent, ActionListener
import csv
import json
import os
import re
import threading
import time


def _percent_to_color(percent):
    """
    Map completion percentage to a semi-translucent color.
    Light red   : incomplete or error (<20)
    Yellow      : >20% goals complete
    Green       : >=90% goals complete
    """
    if percent >= 90:
        base = Color(76, 175, 80)  # green
        alpha = 110
    elif percent >= 20:
        base = Color(255, 235, 59)  # yellow
        alpha = 110
    else:
        base = Color(244, 67, 54)  # light red
        alpha = 110
    return Color(base.getRed(), base.getGreen(), base.getBlue(), alpha)


def _epoch_to_iso(ts):
    if not ts:
        return None
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(ts))


class GoalDefinition(object):
    def __init__(self, key, name, description, detector=None, category="coverage"):
        self.key = key
        self.name = name
        self.description = description
        self.detector = detector
        self.category = category


class GoalState(object):
    def __init__(self, goal):
        self.goal = goal
        self.done = False
        self.automatic = False
        self.updated = None
        self.evidence = []

    def mark(self, automatic=False, value=True, evidence=None):
        now = time.time()
        was_done = self.done
        was_automatic = self.automatic
        changed = self.done != value or (value and not self.automatic and automatic)
        self.done = value
        if value:
            if automatic:
                self.automatic = True
        else:
            # Manual overrides can clear the automatic flag.
            if not automatic:
                self.automatic = False
        self.updated = now
        if value and evidence and (not was_done or (automatic and not was_automatic)):
            entry = {"timestamp": now}
            entry.update(evidence)
            self.evidence.append(entry)
        return changed


class HostProgress(object):
    def __init__(self, host, profile):
        self.host = host
        self.profile = profile
        self.goal_states = dict((g.key, GoalState(g)) for g in profile.goals)
        self.last_seen = time.time()
        self.last_url = None
        self.request_count = 0
        self.response_count = 0
        self.traffic_log = []

    def mark_goal(self, key, automatic=False, value=True, evidence=None):
        state = self.goal_states.get(key)
        if not state:
            return False
        if state.done == value and (not automatic or state.automatic):
            return False
        changed = state.mark(automatic=automatic, value=value, evidence=evidence)
        if changed:
            self.last_seen = time.time()
        return changed

    def completion_rate(self):
        total = len(self.goal_states)
        if total == 0:
            return 0
        done = sum(1 for s in self.goal_states.values() if s.done)
        return int(round((done * 100.0) / total))

    def goals_summary(self):
        total = len(self.goal_states)
        done = sum(1 for s in self.goal_states.values() if s.done)
        return "%d/%d" % (done, total)

    def to_dict(self):
        items = []
        for key, state in self.goal_states.items():
            items.append({
                "key": key,
                "name": state.goal.name,
                "description": state.goal.description,
                "category": state.goal.category,
                "complete": state.done,
                "automatic": state.automatic,
                "last_updated": _epoch_to_iso(state.updated),
                "evidence": [{
                    "timestamp": _epoch_to_iso(ev.get("timestamp")),
                    "url": ev.get("url"),
                    "host": ev.get("host"),
                    "port": ev.get("port"),
                    "protocol": ev.get("protocol"),
                    "request": ev.get("request"),
                    "response": ev.get("response"),
                    "note": ev.get("note"),
                } for ev in state.evidence],
            })
        traffic = []
        for ev in self.traffic_log:
            traffic.append({
                "timestamp": _epoch_to_iso(ev.get("timestamp")),
                "url": ev.get("url"),
                "is_request": ev.get("is_request"),
                "tool_flag": ev.get("tool_flag"),
                "request": ev.get("request"),
                "response": ev.get("response"),
            })
        return {
            "host": self.host,
            "profile": self.profile.name,
            "progress_percent": self.completion_rate(),
            "goals": items,
            "last_seen": _epoch_to_iso(self.last_seen),
            "stats": {
                "requests_observed": self.request_count,
                "responses_observed": self.response_count,
                "goals_done": sum(1 for s in self.goal_states.values() if s.done),
                "goals_total": len(self.goal_states),
            },
            "traffic": traffic,
        }


class GoalProfile(object):
    def __init__(self, name, goals):
        self.name = name
        self.goals = goals


class HostTableModel(AbstractTableModel):
    COLUMNS = ["Host", "Progress", "Goals", "Last Activity"]

    def __init__(self, extender):
        AbstractTableModel.__init__(self)
        self._extender = extender
        self._rows = []

    def refresh(self, rows):
        self._rows = rows
        self.fireTableDataChanged()

    def getRowCount(self):
        return len(self._rows)

    def getColumnCount(self):
        return len(self.COLUMNS)

    def getColumnName(self, column):
        return self.COLUMNS[column]

    def getColumnClass(self, columnIndex):
        if columnIndex == 1:
            return int
        return str

    def getValueAt(self, row, col):
        host_progress = self._rows[row]
        if col == 0:
            return host_progress.host
        if col == 1:
            return host_progress.completion_rate()
        if col == 2:
            return host_progress.goals_summary()
        if col == 3:
            return _epoch_to_iso(host_progress.last_seen) or ""
        return ""

    def getHostAt(self, view_row, table_component=None):
        if table_component:
            model_row = table_component.convertRowIndexToModel(view_row)
        else:
            model_row = view_row
        if model_row < 0 or model_row >= len(self._rows):
            return None
        return self._rows[model_row]


class HostCellRenderer(DefaultTableCellRenderer):
    def __init__(self, model):
        DefaultTableCellRenderer.__init__(self)
        self._model = model

    def getTableCellRendererComponent(self, table_component, value, isSelected, hasFocus, row, column):
        comp = DefaultTableCellRenderer.getTableCellRendererComponent(
            self, table_component, value, isSelected, hasFocus, row, column)
        host_progress = self._model.getHostAt(row, table_component)
        percent = host_progress.completion_rate() if host_progress else 0
        tint = _percent_to_color(percent)
        if isSelected:
            comp.setBackground(tint.darker())
            comp.setForeground(Color.BLACK)
        else:
            comp.setBackground(tint)
            comp.setForeground(Color.BLACK)
        comp.setOpaque(True)
        return comp


class ProgressRenderer(JProgressBar, TableCellRenderer):
    def __init__(self):
        JProgressBar.__init__(self, 0, 100)
        self.setStringPainted(True)
        self.setBorderPainted(False)
        self.setOpaque(True)

    def getTableCellRendererComponent(self, table_component, value, isSelected, hasFocus, row, column):
        percent = 0 if value is None else int(value)
        self.setValue(percent)
        self.setString("%d%%" % percent)
        tint = _percent_to_color(percent)
        self.setBackground(tint)
        self.setForeground(Color.BLACK)
        return self


class GoalDetailPanel(JPanel):
    def __init__(self, extender):
        JPanel.__init__(self)
        self._extender = extender
        self.setLayout(BoxLayout(self, BoxLayout.Y_AXIS))
        self._current_host = None
        self._placeholder = JLabel("Select a host to see goal status.")
        self.add(self._placeholder)

    def show_host(self, host_progress):
        self.removeAll()
        self._current_host = host_progress.host if host_progress else None
        if not host_progress:
            self.add(self._placeholder)
            self.revalidate()
            self.repaint()
            return

        header = JLabel("Goals for %s (profile: %s)" % (host_progress.host, host_progress.profile.name))
        self.add(header)
        for goal in host_progress.profile.goals:
            state = host_progress.goal_states.get(goal.key)
            checkbox = JCheckBox(goal.name)
            checkbox.setSelected(state.done)
            checkbox.setToolTipText(goal.description)
            # Allow manual override, but annotate auto goals.
            if goal.detector is not None:
                checkbox.setText(goal.name + " (auto)")
            checkbox.addItemListener(self._make_listener(host_progress.host, goal.key))
            row = JPanel()
            row.setLayout(BoxLayout(row, BoxLayout.X_AXIS))
            row.add(checkbox)
            evidence_btn = JButton("View evidence")
            evidence_btn.addActionListener(self._make_evidence_listener(host_progress.host, goal.key))
            evidence_btn.setEnabled(True)
            row.add(evidence_btn)
            repeater_btn = JButton("Send to Repeater")
            repeater_btn.addActionListener(self._make_repeater_listener(host_progress.host, goal.key))
            repeater_btn.setEnabled(True)
            row.add(repeater_btn)
            self.add(row)
            desc = JLabel(" - %s" % goal.description)
            self.add(desc)
        self.revalidate()
        self.repaint()

    def _make_listener(self, host, goal_key):
        extender = self._extender

        class _Listener(ItemListener):
            def itemStateChanged(self, event):
                selected = event.getStateChange() == ItemEvent.SELECTED
                extender.manual_goal_toggle(host, goal_key, selected)

        return _Listener()

    def _make_evidence_listener(self, host, goal_key):
        extender = self._extender

        class _Listener(ActionListener):
            def actionPerformed(self, event):
                extender.show_goal_evidence(host, goal_key)

        return _Listener()

    def _make_repeater_listener(self, host, goal_key):
        extender = self._extender

        class _Listener(ActionListener):
            def actionPerformed(self, event):
                extender.send_goal_evidence_to_repeater(host, goal_key)

        return _Listener()


class _TableSelectionListener(ListSelectionListener):
    def __init__(self, extender):
        self._extender = extender

    def valueChanged(self, event):
        self._extender._on_row_selected(event)


class _ScopeToggleListener(ItemListener):
    def __init__(self, extender):
        self._extender = extender

    def itemStateChanged(self, event):
        selected = event.getStateChange() == ItemEvent.SELECTED
        self._extender._scope_only = selected
        self._extender._refresh_table_async()


class EpitaphExtender(IBurpExtender, ITab, IHttpListener, IExtensionStateListener):
    def __init__(self):
        self.callbacks = None
        self.helpers = None
        self._profile = GoalProfile("Default", [])
        self._hosts = {}
        self._lock = threading.Lock()
        self._table_model = HostTableModel(self)
        self._table = None
        self._goal_panel = GoalDetailPanel(self)
        self._goal_scroll = None
        self._export_field = None
        self._goal_template_field = None
        self._scope_only = True
        self._root_panel = None

    def _make_scope_listener(self):
        return _ScopeToggleListener(self)

    def _hydrate_async(self):
        t = threading.Thread(target=self._hydrate_from_history)
        t.setDaemon(True)
        t.start()

    def _hydrate_from_history(self):
        # Populate from existing proxy history so users can load state without replaying traffic.
        history = None
        try:
            history = self.callbacks.getProxyHistory() if self.callbacks else None
        except Exception as exc:
            if self.callbacks:
                self.callbacks.printError("Hydration: unable to read proxy history: %s" % exc)
            return
        if not history:
            return
        count = 0
        for item in history:
            try:
                tool_flag = None
                try:
                    tool_flag = item.getToolFlag()
                except Exception:
                    tool_flag = None
                # Simulate both request and response processing if present.
                self.processHttpMessage(tool_flag, True, item)
                if item.getResponse():
                    self.processHttpMessage(tool_flag, False, item)
                count += 1
            except Exception as exc:
                if self.callbacks:
                    self.callbacks.printError("Hydration error: %s" % exc)
        if self.callbacks:
            self.callbacks.printOutput("Hydrated %d history items into Epitaph." % count)
        self._refresh_table_async()

    #
    # IBurpExtender implementation
    #
    def registerExtenderCallbacks(self, callbacks):
        self.callbacks = callbacks
        self.helpers = callbacks.getHelpers()
        callbacks.setExtensionName("Epitaph - Goal Tracker")
        self._build_profile()
        self._build_ui()
        callbacks.addSuiteTab(self)
        callbacks.registerHttpListener(self)
        callbacks.registerExtensionStateListener(self)
        callbacks.printOutput("Epitaph loaded. Tracking profile: %s" % self._profile.name)
        self._hydrate_async()

    #
    # Goal and detection setup
    #
    def _default_goals(self):
        return [
            GoalDefinition(
                "inject_special_chars",
                "Injection markers seen",
                "Special characters (< > \" ') observed in parameters for this host.",
                detector=self._detect_injection_markers,
                category="injection"),
            GoalDefinition(
                "post_or_put_seen",
                "State-changing method seen",
                "Observed POST/PUT/PATCH/DELETE request for this host.",
                detector=self._detect_state_changing_method,
                category="coverage"),
            GoalDefinition(
                "auth_surface",
                "Authentication surface touched",
                "Request path hints at authentication (login/auth/signin/oauth).",
                detector=self._detect_auth_surface,
                category="coverage"),
            GoalDefinition(
                "error_response_seen",
                "Error path captured",
                "A non-2xx response observed for this host.",
                detector=self._detect_error_response,
                category="robustness"),
            GoalDefinition(
                "manual_creative",
                "Manual creative testing",
                "Toggle when you complete targeted/manual probing.",
                detector=None,
                category="manual"),
        ]

    def _build_profile(self):
        self._profile = GoalProfile("Default Injection Coverage", self._default_goals())

    def _sanitize_goal_key(self, value, fallback_prefix="goal"):
        if value is None:
            return None
        key = re.sub(r"[^a-zA-Z0-9]+", "_", value.lower()).strip("_")
        if not key:
            key = fallback_prefix
        return key

    def _in_scope(self, url):
        if not self._scope_only:
            return True
        if not self.callbacks or url is None:
            return True
        try:
            return self.callbacks.isInScope(url)
        except Exception:
            return True

    def _ensure_unique_key(self, key, used_keys):
        base = key or "goal"
        candidate = base
        counter = 2
        while candidate in used_keys:
            candidate = "%s_%d" % (base, counter)
            counter += 1
        return candidate

    def _make_manual_goal(self, key, name, description, category):
        return GoalDefinition(
            key,
            name or key,
            description or (name or key),
            detector=None,
            category=category or "manual",
        )

    def _load_goal_template(self, path, include_defaults=True):
        if not path:
            raise ValueError("Template path is empty.")
        if not os.path.isfile(path):
            raise IOError("Template file not found: %s" % path)
        with open(path, "r") as handle:
            raw = handle.read()
        lines = [ln.strip() for ln in raw.splitlines() if ln.strip()]
        if not lines:
            raise ValueError("Template file is empty: %s" % path)

        sample = "\n".join(lines[:5])
        delimiter = None
        has_header = False
        try:
            dialect = csv.Sniffer().sniff(sample, delimiters=",;|\t")
            delimiter = dialect.delimiter
            has_header = csv.Sniffer().has_header(sample)
        except Exception:
            delimiter = None

        rows = []
        if delimiter:
            if has_header:
                reader = csv.DictReader(lines, delimiter=delimiter)
            else:
                reader = csv.reader(lines, delimiter=delimiter)
            for row in reader:
                if isinstance(row, dict):
                    lowered = dict((k.lower(), v) for k, v in row.items())
                    key = (lowered.get("key") or lowered.get("id") or lowered.get("slug") or "").strip()
                    name = (lowered.get("name") or lowered.get("title") or "").strip()
                    desc = (lowered.get("description") or lowered.get("desc") or "").strip()
                    category = (lowered.get("category") or lowered.get("group") or "manual").strip() or "manual"
                else:
                    cells = [c.strip() for c in row]
                    while len(cells) < 4:
                        cells.append("")
                    key, name, desc, category = cells[:4]
                rows.append((key, name, desc, category))
        else:
            for line in lines:
                parts = [p.strip() for p in line.split("|")] if "|" in line else [line]
                while len(parts) < 4:
                    parts.append("")
                if len(parts) == 1:
                    key = ""
                    name = parts[0]
                    desc = parts[0]
                    category = "manual"
                else:
                    key, name, desc, category = parts[:4]
                rows.append((key, name, desc, category))

        base_goals = self._default_goals() if include_defaults else []
        base_by_key = dict((g.key, g) for g in base_goals)
        used_keys = set(base_by_key.keys())
        custom_goals = []
        touched_default = False
        for key, name, desc, category in rows:
            sanitized = self._sanitize_goal_key(key or name)
            if not sanitized:
                continue
            if sanitized in base_by_key:
                base_goal = base_by_key[sanitized]
                if name:
                    base_goal.name = name
                if desc:
                    base_goal.description = desc
                if category:
                    base_goal.category = category
                touched_default = True
                continue
            unique_key = self._ensure_unique_key(sanitized, used_keys)
            used_keys.add(unique_key)
            custom_goals.append(self._make_manual_goal(unique_key, name, desc, category))

        if not custom_goals and not touched_default:
            raise ValueError("No goals parsed from template: %s" % path)

        profile_name = "Custom: %s" % os.path.basename(path)
        return GoalProfile(profile_name, base_goals + custom_goals)

    def _apply_profile(self, profile):
        with self._lock:
            self._profile = profile
            for host_progress in self._hosts.values():
                new_states = {}
                for goal in profile.goals:
                    existing = host_progress.goal_states.get(goal.key)
                    if existing:
                        existing.goal = goal
                        new_states[goal.key] = existing
                    else:
                        new_states[goal.key] = GoalState(goal)
                host_progress.goal_states = new_states
                host_progress.profile = profile
        self._refresh_table_async()

    #
    # UI
    #
    def _build_ui(self):
        self._root_panel = JPanel(BorderLayout())

        toolbar = JPanel()
        toolbar.setLayout(BoxLayout(toolbar, BoxLayout.X_AXIS))
        load_button = JButton("Load Goals", actionPerformed=self._handle_load_template)
        self._goal_template_field = JTextField(os.path.join(System.getProperty("user.dir"), "epitaph-goals.csv"), 24)
        export_button = JButton("Export JSON", actionPerformed=self._handle_export)
        self._export_field = JTextField(os.path.join(System.getProperty("user.dir"), "epitaph-report.json"), 30)
        scope_checkbox = JCheckBox("Scope only", self._scope_only)
        scope_checkbox.addItemListener(self._make_scope_listener())
        toolbar.add(scope_checkbox)
        toolbar.add(JLabel("Template path: "))
        toolbar.add(self._goal_template_field)
        toolbar.add(load_button)
        toolbar.add(JLabel("Export path: "))
        toolbar.add(self._export_field)
        toolbar.add(export_button)
        toolbar.setMaximumSize(Dimension(10000, 40))

        self._table = JTable(self._table_model)
        self._table.setFillsViewportHeight(True)
        self._table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION)
        self._table.getSelectionModel().addListSelectionListener(_TableSelectionListener(self))
        self._table.getColumnModel().getColumn(0).setPreferredWidth(180)
        self._table.getColumnModel().getColumn(1).setPreferredWidth(90)
        self._table.getColumnModel().getColumn(2).setPreferredWidth(80)
        self._table.getColumnModel().getColumn(3).setPreferredWidth(180)
        self._table.getColumnModel().getColumn(0).setCellRenderer(HostCellRenderer(self._table_model))
        self._table.getColumnModel().getColumn(1).setCellRenderer(ProgressRenderer())

        table_scroll = JScrollPane(self._table)
        table_scroll.setPreferredSize(Dimension(500, 240))

        self._goal_scroll = JScrollPane(self._goal_panel)
        self._goal_scroll.setPreferredSize(Dimension(500, 200))

        split = JSplitPane(JSplitPane.VERTICAL_SPLIT)
        split.setTopComponent(table_scroll)
        split.setBottomComponent(self._goal_scroll)
        split.setResizeWeight(0.6)

        self._root_panel.add(toolbar, BorderLayout.NORTH)
        self._root_panel.add(split, BorderLayout.CENTER)

    def getTabCaption(self):
        return "Epitaph"

    def getUiComponent(self):
        return self._root_panel

    def _on_row_selected(self, event):
        if event.getValueIsAdjusting():
            return
        selected = self._table.getSelectedRow()
        host_progress = self._table_model.getHostAt(selected, self._table) if selected >= 0 else None
        self._goal_panel.show_host(host_progress)

    def _handle_export(self, _event):
        path = self._export_field.getText()
        try:
            written = self.export_json(path)
            self.callbacks.printOutput("Exported testing record to %s" % written)
        except Exception as exc:  # pragma: no cover - UI feedback only
            self.callbacks.printError("Failed to export: %s" % exc)

    def _handle_load_template(self, _event):
        path = self._goal_template_field.getText() if self._goal_template_field else None
        try:
            profile = self._load_goal_template(path)
            self._apply_profile(profile)
            if self.callbacks:
                self.callbacks.printOutput("Loaded %d goals from %s (profile: %s)" % (
                    len(profile.goals), path, profile.name))
        except Exception as exc:  # pragma: no cover - UI feedback only
            if self.callbacks:
                self.callbacks.printError("Failed to load goals: %s" % exc)

    #
    # IHttpListener implementation
    #
    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        try:
            request_info = self.helpers.analyzeRequest(messageInfo)
            service = messageInfo.getHttpService()
            host = service.getHost()
            if not host:
                return
            in_scope = True
            if self._scope_only:
                try:
                    in_scope = self.callbacks.isInScope(request_info.getUrl())
                except Exception:
                    in_scope = True
            if not in_scope:
                return
            with self._lock:
                host_progress = self._hosts.get(host)
                if not host_progress:
                    host_progress = HostProgress(host, self._profile)
                    self._hosts[host] = host_progress
                host_progress.last_url = request_info.getUrl()
                if messageIsRequest:
                    host_progress.request_count += 1
                else:
                    host_progress.response_count += 1
                snapshot = self._capture_message_snapshot(messageInfo, messageIsRequest, request_info, toolFlag)
                host_progress.traffic_log.append(snapshot)
            self._evaluate_goals(host_progress, messageInfo, messageIsRequest, request_info=request_info, tool_flag=toolFlag)
        except Exception as exc:  # pragma: no cover - defensive logging
            if self.callbacks:
                self.callbacks.printError("Epitaph processing error: %s" % exc)

    def _evaluate_goals(self, host_progress, messageInfo, is_request, request_info=None, tool_flag=None):
        if request_info is None:
            request_info = self.helpers.analyzeRequest(messageInfo)
        response_info = None
        if not is_request and messageInfo.getResponse():
            response_info = self.helpers.analyzeResponse(messageInfo.getResponse())
        changed = False
        evidence_cache = None
        for goal in self._profile.goals:
            if goal.detector is None:
                continue
            try:
                if goal.detector(host_progress, messageInfo, request_info, response_info, is_request):
                    if evidence_cache is None:
                        evidence_cache = self._capture_goal_evidence(messageInfo, request_info=request_info, tool_flag=tool_flag)
                    with self._lock:
                        changed = host_progress.mark_goal(goal.key, automatic=True, value=True, evidence=evidence_cache) or changed
            except Exception as exc:  # pragma: no cover - defensive logging
                self.callbacks.printError("Detector %s failed: %s" % (goal.key, exc))
        if changed:
            self._refresh_table_async()

    def _capture_goal_evidence(self, messageInfo, request_info=None, tool_flag=None):
        request_text = None
        response_text = None
        service = None
        try:
            service = messageInfo.getHttpService()
        except Exception:
            service = None
        try:
            raw_req = messageInfo.getRequest()
            if raw_req:
                request_text = self.helpers.bytesToString(raw_req)
        except Exception:
            pass
        try:
            raw_resp = messageInfo.getResponse()
            if raw_resp:
                response_text = self.helpers.bytesToString(raw_resp)
        except Exception:
            pass
        if request_text is None and response_text is None:
            return None
        host = service.getHost() if service else None
        port = service.getPort() if service else None
        protocol = service.getProtocol() if service else None
        return {
            "timestamp": time.time(),
            "url": str(request_info.getUrl()) if request_info and request_info.getUrl() else None,
            "host": host,
            "port": port,
            "protocol": protocol,
            "tool_flag": int(tool_flag) if tool_flag is not None else None,
            "request": request_text,
            "response": response_text,
        }

    def _capture_message_snapshot(self, messageInfo, is_request, request_info, tool_flag):
        request_text = None
        response_text = None
        try:
            raw_req = messageInfo.getRequest()
            if raw_req:
                request_text = self.helpers.bytesToString(raw_req)
        except Exception:
            pass
        try:
            raw_resp = messageInfo.getResponse()
            if raw_resp:
                response_text = self.helpers.bytesToString(raw_resp)
        except Exception:
            pass
        return {
            "timestamp": time.time(),
            "url": str(request_info.getUrl()) if request_info and request_info.getUrl() else None,
            "is_request": bool(is_request),
            "tool_flag": int(tool_flag) if tool_flag is not None else None,
            "request": request_text,
            "response": response_text,
        }

    def show_goal_evidence(self, host, goal_key):
        with self._lock:
            host_progress = self._hosts.get(host)
            state = host_progress.goal_states.get(goal_key) if host_progress else None
            evidence = list(state.evidence) if state else []
            goal_name = state.goal.name if state else goal_key
        if not evidence:
            JOptionPane.showMessageDialog(self._root_panel, "No evidence recorded for %s" % goal_name, "Goal evidence", JOptionPane.INFORMATION_MESSAGE)
            return
        lines = []
        for idx, ev in enumerate(evidence, 1):
            ts = _epoch_to_iso(ev.get("timestamp"))
            url = ev.get("url") or ""
            tool = ev.get("tool_flag")
            host_val = ev.get("host") or host
            port_val = ev.get("port")
            proto = ev.get("protocol")
            lines.append("Entry %d%s%s" % (
                idx,
                ("  @ %s" % ts) if ts else "",
                ("  tool=%s" % tool) if tool is not None else "",
            ))
            if host_val or port_val or proto:
                lines.append("Service: %s%s%s" % (
                    host_val or "",
                    (":%s" % port_val) if port_val else "",
                    (" (%s)" % proto) if proto else "",
                ))
            if url:
                lines.append("URL: %s" % url)
            lines.append("Request:\n%s" % (ev.get("request") or "(none)"))
            if ev.get("response"):
                lines.append("Response:\n%s" % ev.get("response"))
            lines.append("-" * 60)
        text = "\n".join(lines)
        area = JTextArea(text)
        area.setEditable(False)
        area.setLineWrap(False)
        scroll = JScrollPane(area)
        scroll.setPreferredSize(Dimension(900, 500))
        JOptionPane.showMessageDialog(self._root_panel, scroll, "Evidence for %s" % goal_name, JOptionPane.INFORMATION_MESSAGE)

    def send_goal_evidence_to_repeater(self, host, goal_key):
        if not self.callbacks or not self.helpers:
            JOptionPane.showMessageDialog(self._root_panel, "Burp callbacks unavailable; cannot send to Repeater.", "Send to Repeater", JOptionPane.ERROR_MESSAGE)
            return
        with self._lock:
            host_progress = self._hosts.get(host)
            state = host_progress.goal_states.get(goal_key) if host_progress else None
            evidence = list(state.evidence) if state else []
            goal_name = state.goal.name if state else goal_key
        if not evidence:
            JOptionPane.showMessageDialog(self._root_panel, "No evidence recorded for %s" % goal_name, "Send to Repeater", JOptionPane.INFORMATION_MESSAGE)
            return
        sent = 0
        for idx, ev in enumerate(evidence, 1):
            req_text = ev.get("request")
            if not req_text:
                continue
            host_val = ev.get("host") or host or "host"
            proto = (ev.get("protocol") or "https").lower()
            port_val = ev.get("port")
            if port_val is None:
                port_val = 443 if proto == "https" else 80
            try:
                req_bytes = self.helpers.stringToBytes(req_text)
                tab_name = "%s:%s %s #%d" % (host_val, port_val, goal_name, idx)
                self.callbacks.sendToRepeater(host_val, int(port_val), proto == "https", req_bytes, tab_name)
                sent += 1
            except Exception as exc:
                if self.callbacks:
                    self.callbacks.printError("Send to Repeater failed for %s #%d: %s" % (goal_name, idx, exc))
        JOptionPane.showMessageDialog(self._root_panel, "Sent %d request(s) for %s to Repeater." % (sent, goal_name), "Send to Repeater", JOptionPane.INFORMATION_MESSAGE)

    #
    # Goal detectors
    #
    def _detect_injection_markers(self, host_progress, messageInfo, request_info, response_info, is_request):
        if not is_request:
            return False
        params = request_info.getParameters()
        special_chars = set(['<', '>', '"', "'"])
        for param in params:
            val = param.getValue()
            if any(ch in val for ch in special_chars):
                return True
        # If parameters are not parsed (e.g., raw body), fall back to body search.
        raw = self.helpers.bytesToString(messageInfo.getRequest())
        for ch in special_chars:
            if ch in raw:
                return True
        return False

    def _detect_state_changing_method(self, host_progress, messageInfo, request_info, response_info, is_request):
        if not is_request:
            return False
        method = request_info.getMethod().upper()
        return method in ("POST", "PUT", "PATCH", "DELETE")

    def _detect_auth_surface(self, host_progress, messageInfo, request_info, response_info, is_request):
        if not is_request:
            return False
        url = request_info.getUrl()
        if not url:
            return False
        path = url.getPath() or ""
        return re.search(r"(auth|login|signin|oauth|sso|mfa)", path, re.I) is not None

    def _detect_error_response(self, host_progress, messageInfo, request_info, response_info, is_request):
        if is_request or not response_info:
            return False
        status = response_info.getStatusCode()
        return status < 200 or status >= 400

    #
    # Manual goal toggling from UI
    #
    def manual_goal_toggle(self, host, goal_key, value):
        with self._lock:
            host_progress = self._hosts.get(host)
            if not host_progress:
                return
            changed = host_progress.mark_goal(goal_key, automatic=False, value=value)
        if changed:
            self._refresh_table_async()

    #
    # Table/UI updates
    #
    def _refresh_table_async(self):
        # Ensure UI updates happen on the Swing thread.
        extender = self

        class _Update(Runnable):
            def run(self):
                extender._refresh_table()

        SwingUtilities.invokeLater(_Update())

    def _refresh_table(self):
        with self._lock:
            rows = list(self._hosts.values())
        if self._scope_only:
            rows = [hp for hp in rows if self._in_scope(hp.last_url)]
        rows.sort(key=lambda hp: hp.host.lower())
        self._table_model.refresh(rows)
        selected = self._table.getSelectedRow()
        host_progress = self._table_model.getHostAt(selected, self._table) if selected >= 0 else None
        self._goal_panel.show_host(host_progress)
        if self._goal_scroll:
            self._goal_scroll.getVerticalScrollBar().setValue(0)

    #
    # Export
    #
    def export_json(self, path=None):
        if not path:
            path = self._export_field.getText()
        with self._lock:
            hosts = [hp.to_dict() for hp in self._hosts.values()]
        report = {
            "exported_at": _epoch_to_iso(time.time()),
            "profile": self._profile.name,
            "host_count": len(hosts),
            "hosts": hosts,
            "notes": "Generated by Epitaph Burp extension. Values represent observed test coverage per host.",
        }
        with open(path, "w") as handle:
            json.dump(report, handle, indent=2, sort_keys=True)
        return path

    #
    # IExtensionStateListener implementation
    #
    def extensionUnloaded(self):
        # Persist a final snapshot on unload.
        try:
            self.export_json(self._export_field.getText())
        except Exception:
            pass


# Entry point for Burp.
def getBurpExtension():
    return EpitaphExtender()


# Burp Python loader expects a class named BurpExtender implementing IBurpExtender.
class BurpExtender(EpitaphExtender):
    def registerExtenderCallbacks(self, callbacks):
        # Delegate to base implementation.
        super(BurpExtender, self).registerExtenderCallbacks(callbacks)
