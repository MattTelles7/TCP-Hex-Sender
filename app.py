import re
import select
import socket
import sys
import time
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

from PySide6.QtCore import QObject, QThread, Signal, Slot
from PySide6.QtGui import QFont, QIcon, QTextOption
from PySide6.QtWidgets import (
    QApplication,
    QComboBox,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QSpinBox,
    QVBoxLayout,
    QWidget,
)

# --------------------------------------------------------------------------------------
# Regex helpers for user-entered hex input
# --------------------------------------------------------------------------------------
HEX_CLEAN_RE = re.compile(r"\s+", re.MULTILINE)  # remove whitespace
HEX_PREFIX_RE = re.compile(r"0x", re.IGNORECASE)  # remove "0x" prefixes

# --------------------------------------------------------------------------------------
# Socket timing defaults
# --------------------------------------------------------------------------------------
CONNECT_TIMEOUT_S = 3.0

# Raw device-style read behavior:
# - Wait up to FIRST_BYTE_TIMEOUT_S for the first response byte.
# - Then keep reading until no new bytes arrive for RAW_IDLE_TIMEOUT_S.
# - Bail out completely after RAW_MAX_TOTAL_TIMEOUT_S.
FIRST_BYTE_TIMEOUT_S = 5.0
RAW_IDLE_TIMEOUT_S = 0.75
RAW_MAX_TOTAL_TIMEOUT_S = 10.0

# --------------------------------------------------------------------------------------
# Auto-ACK behavior:
# If we receive a message whose first byte is NOT one of these, we immediately send 0x06.
# (Common in terminal protocols: ACK=0x06, NAK=0x15, EOT=0x04.)
# --------------------------------------------------------------------------------------
ACK_BYTE = b"\x06"
NO_ACK_PREFIXES = {0x06, 0x15, 0x04}

# --------------------------------------------------------------------------------------
# History persistence (YAML stream: each record appended as its own document starting with ---)
# This is easy to append to and easy to parse with any YAML parser (load_all).
# --------------------------------------------------------------------------------------
HISTORY_PATH = Path(__file__).resolve().parent / "tcp_hex_history.yaml"

# --------------------------------------------------------------------------------------
# Preset definitions:
# NOTE: You should replace the hex strings with your real terminal command bytes.
# The UI will still work even if some are blank, but sending blank bytes is usually meaningless.
# --------------------------------------------------------------------------------------
PRESET_HEX: dict[str, str] = {
    "Ping": "0F31310E",
    "Cancel": "0237320306",
    "Pair": "",                 # TODO: fill with real bytes
    "Get Card": "",             # TODO: fill with real bytes
    "Start Transaction": "",    # TODO: fill with real bytes
}
CUSTOM_OPTION = "Custom… (requires label)"


# --------------------------------------------------------------------------------------
# Data containers
# --------------------------------------------------------------------------------------
@dataclass
class HexParseResult:
    is_valid: bool
    error: str
    payload: bytes
    normalized_hex: str


@dataclass
class RawReadResult:
    raw_response: bytes
    note: str
    peer_closed: bool
    ack_sent: bool


class ConnectionClosedError(Exception):
    """Raised when the remote peer closes the TCP connection cleanly."""
    pass


# --------------------------------------------------------------------------------------
# Utility formatting helpers
# --------------------------------------------------------------------------------------
def timestamp_now() -> str:
    """Return local timestamp with milliseconds, suitable for history UI/log."""
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]


def bytes_to_hex_spaced(data: bytes) -> str:
    """Convert bytes to 'AA BB CC' style hex for readability."""
    if not data:
        return "(empty)"
    return " ".join(f"{byte:02X}" for byte in data)


def bytes_preview(data: bytes) -> str:
    """
    Convert bytes to a human-friendly preview:
    - ASCII printable bytes show as characters
    - Non-printable bytes show as <0xNN>
    """
    if not data:
        return "(empty)"

    out: list[str] = []
    for byte in data:
        if 0x20 <= byte <= 0x7E:
            out.append(chr(byte))
        else:
            out.append(f"<0x{byte:02X}>")
    return "".join(out)


def parse_hex_input(raw_text: str) -> HexParseResult:
    """
    Parse user-entered hex into bytes.
    Accepts spaces/newlines and optional 0x prefixes.
    """
    cleaned = HEX_CLEAN_RE.sub("", raw_text)
    cleaned = HEX_PREFIX_RE.sub("", cleaned)

    if cleaned == "":
        # Empty input is "valid" hex, but it sends zero bytes.
        return HexParseResult(True, "", b"", "(empty)")

    if re.search(r"[^0-9A-Fa-f]", cleaned):
        return HexParseResult(False, "Invalid hex: non-hex character found.", b"", "")

    if len(cleaned) % 2 != 0:
        return HexParseResult(False, "Invalid hex: odd number of hex digits.", b"", "")

    try:
        payload = bytes.fromhex(cleaned)
    except ValueError:
        return HexParseResult(False, "Invalid hex input.", b"", "")

    normalized_hex = bytes_to_hex_spaced(payload)
    return HexParseResult(True, "", payload, normalized_hex)


# --------------------------------------------------------------------------------------
# YAML writing helpers (no external dependencies)
# We append each record as a YAML document (---) so we do not need to rewrite the whole file.
# --------------------------------------------------------------------------------------
def _yaml_escape_string(value: str) -> str:
    """
    Minimal safe YAML double-quoted string escaping.
    Keeps everything single-line by escaping newlines/carriage returns.
    """
    value = value.replace("\\", "\\\\").replace('"', '\\"')
    value = value.replace("\r", "\\r").replace("\n", "\\n")
    return f'"{value}"'


def _yaml_scalar(value: Any) -> str:
    """Serialize simple scalar values to YAML-friendly strings."""
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return str(value)
    return _yaml_escape_string(str(value))


def append_history_yaml(record: dict[str, Any]) -> None:
    """
    Append a single history record to HISTORY_PATH as a YAML document.
    This produces a YAML stream (multiple docs). Most YAML parsers can load it with load_all().
    """
    HISTORY_PATH.parent.mkdir(parents=True, exist_ok=True)
    with HISTORY_PATH.open("a", encoding="utf-8") as f:
        f.write("---\n")
        for key, val in record.items():
            f.write(f"{key}: {_yaml_scalar(val)}\n")


# --------------------------------------------------------------------------------------
# Low-level network read with auto-ACK
# --------------------------------------------------------------------------------------
def read_raw_response_wait_idle(
    sock: socket.socket,
    initial_buffer: bytes,
    first_byte_timeout_s: float = FIRST_BYTE_TIMEOUT_S,
    idle_timeout_s: float = RAW_IDLE_TIMEOUT_S,
    max_total_timeout_s: float = RAW_MAX_TOTAL_TIMEOUT_S,
    auto_ack: bool = True,
) -> RawReadResult:
    """
    Read bytes from the socket using a device-friendly strategy:

    1) If no initial bytes exist, wait up to first_byte_timeout_s for the first byte to arrive.
    2) Then drain the socket until we see idle_timeout_s with no new bytes.
    3) Also enforce a max_total_timeout_s so we don't get stuck forever.
    4) Auto-ACK: if the first received byte is NOT 0x06/0x15/0x04, immediately send 0x06.

    Returns:
      - raw_response: all bytes received
      - note: debug text describing why we stopped reading
      - peer_closed: True if recv() returned b""
      - ack_sent: True if we sent 0x06 due to the first byte rule
    """
    body = bytearray(initial_buffer)
    peer_closed = False
    start_time = time.monotonic()
    stop_reason = ""
    ack_sent = False

    # If we don't already have buffered bytes, wait for the first response byte.
    if not body:
        ready, _, _ = select.select([sock], [], [], first_byte_timeout_s)
        if not ready:
            return RawReadResult(
                raw_response=b"",
                note=f"No response bytes received within first-byte timeout ({first_byte_timeout_s:.1f} s).",
                peer_closed=False,
                ack_sent=False,
            )

    # Drain loop: read until idle or max-total timeout.
    while True:
        elapsed = time.monotonic() - start_time
        remaining_total = max_total_timeout_s - elapsed
        if remaining_total <= 0:
            stop_reason = f"max-total timeout ({max_total_timeout_s:.1f} s)"
            break

        sock.settimeout(min(idle_timeout_s, remaining_total))
        try:
            chunk = sock.recv(4096)
            if chunk == b"":
                peer_closed = True
                stop_reason = "peer closed"
                break

            # Add bytes to our buffer
            body.extend(chunk)

            # Auto-ACK decision happens as soon as we know the first byte.
            if auto_ack and not ack_sent and len(body) > 0:
                first = body[0]
                if first not in NO_ACK_PREFIXES:
                    try:
                        sock.sendall(ACK_BYTE)
                        ack_sent = True
                    except OSError:
                        # If sending ACK fails, we still keep what we read.
                        pass

            # Continue draining until we hit idle timeout.
        except socket.timeout:
            stop_reason = f"idle timeout ({int(idle_timeout_s * 1000)} ms)"
            break

    total_elapsed = time.monotonic() - start_time
    note = (
        f"Raw read: first-byte wait {first_byte_timeout_s:.1f}s, "
        f"read-until-idle {int(idle_timeout_s * 1000)} ms, "
        f"max-total {max_total_timeout_s:.1f}s, "
        f"stop={stop_reason}, bytes={len(body)}, elapsed={total_elapsed:.3f}s, "
        f"auto_ack={'yes' if ack_sent else 'no'}."
    )
    return RawReadResult(raw_response=bytes(body), note=note, peer_closed=peer_closed, ack_sent=ack_sent)


# --------------------------------------------------------------------------------------
# Worker thread object:
# All socket work happens here so the GUI thread stays responsive.
# --------------------------------------------------------------------------------------
class TcpWorker(QObject):
    connected = Signal(str, int)                   # host, port
    disconnected = Signal(str)                     # reason
    send_result = Signal(str, bytes, bytes, str)   # label, sent, received, note
    send_error = Signal(str, bytes, str)           # label, sent, error message
    error = Signal(str)                            # general errors not tied to a specific send

    def __init__(self) -> None:
        super().__init__()
        self._sock: Optional[socket.socket] = None
        self._host = ""
        self._port = 0
        self._recv_buffer = b""

    @property
    def is_connected(self) -> bool:
        return self._sock is not None

    @Slot(str, int)
    def connect_to_host(self, host: str, port: int) -> None:
        """Create and connect a TCP socket to the target host/port."""
        if self._sock is not None:
            self.disconnected.emit("Already connected. Disconnect first.")
            return

        # Resolve host name -> possible IPv4/IPv6 candidates
        try:
            addr_infos = socket.getaddrinfo(host, port, socket.AF_UNSPEC, socket.SOCK_STREAM)
        except OSError as exc:
            self.error.emit(f"Connect failed: {exc}")
            return

        connect_error: Optional[Exception] = None
        sock: Optional[socket.socket] = None

        # Try each resolved address until one connects
        for family, socktype, proto, _canonname, sockaddr in addr_infos:
            candidate = socket.socket(family, socktype, proto)
            candidate.settimeout(CONNECT_TIMEOUT_S)
            try:
                candidate.connect(sockaddr)
                sock = candidate
                break
            except Exception as exc:
                connect_error = exc
                try:
                    candidate.close()
                except OSError:
                    pass

        if sock is None:
            self.error.emit(f"Connect failed: {connect_error}")
            return

        self._sock = sock
        self._host = host
        self._port = port
        self._recv_buffer = b""
        self.connected.emit(host, port)

    @Slot()
    def disconnect_from_host(self) -> None:
        """Close socket and reset state."""
        if self._sock is None:
            self.disconnected.emit("Disconnected.")
            return

        try:
            self._sock.close()
        except OSError:
            pass

        self._sock = None
        self._recv_buffer = b""
        self.disconnected.emit("Disconnected.")

    @Slot(bytes, str)
    def send_payload(self, payload: bytes, label: str) -> None:
        """
        Send bytes to the device then read bytes back.

        Yes: you are writing to the socket (sendall) and then listening (recv).
        """
        if self._sock is None:
            self.send_error.emit(label, payload, "Not connected.")
            return

        try:
            # WRITE: send user-provided bytes
            self._sock.sendall(payload)

            # READ: raw read, with auto-ACK behavior
            raw_result = read_raw_response_wait_idle(
                self._sock,
                initial_buffer=self._recv_buffer,
                first_byte_timeout_s=FIRST_BYTE_TIMEOUT_S,
                idle_timeout_s=RAW_IDLE_TIMEOUT_S,
                max_total_timeout_s=RAW_MAX_TOTAL_TIMEOUT_S,
                auto_ack=True,
            )

            # We consumed all pending bytes (we don't keep leftovers in this simple model)
            self._recv_buffer = b""

            if raw_result.raw_response:
                note = raw_result.note
                self.send_result.emit(label, payload, raw_result.raw_response, note)
            else:
                self.send_error.emit(label, payload, raw_result.note)

            # If the peer closed, clean up connection state
            if raw_result.peer_closed:
                try:
                    self._sock.close()
                except OSError:
                    pass
                self._sock = None
                self._recv_buffer = b""
                self.disconnected.emit("Peer closed the connection.")

        except (ConnectionClosedError, OSError) as exc:
            try:
                if self._sock is not None:
                    self._sock.close()
            except OSError:
                pass
            self._sock = None
            self._recv_buffer = b""
            self.send_error.emit(label, payload, f"Send/read failed: {exc}")
            self.disconnected.emit("Socket closed due to error.")


# --------------------------------------------------------------------------------------
# Main UI window
# --------------------------------------------------------------------------------------
class MainWindow(QMainWindow):
    # Signals from UI thread -> worker thread
    request_connect = Signal(str, int)
    request_disconnect = Signal()
    request_send = Signal(bytes, str)  # payload, label

    def __init__(self) -> None:
        super().__init__()

        self.setWindowTitle("TCP Hex Sender")

        # Optional icon support (same directory as the script)
        icon_path = Path(__file__).resolve().parent / "icon.jpg"
        if icon_path.exists():
            self.setWindowIcon(QIcon(str(icon_path)))

        self.resize(1000, 800)

        # Runtime state used by the UI
        self._is_connected = False
        self._connected_host = ""
        self._connected_port = 0
        self._last_hex_result = parse_hex_input("")
        self._history_blocks: list[str] = []

        self._build_ui()
        self._build_worker()
        self._wire_events()
        self._refresh_send_button_state()

    # --------------------------- UI construction ---------------------------

    def _build_ui(self) -> None:
        root = QWidget()
        root_layout = QVBoxLayout(root)
        root_layout.setContentsMargins(10, 10, 10, 10)
        root_layout.setSpacing(8)

        # Top grid: connection settings + action/label fields
        grid = QGridLayout()
        grid.setHorizontalSpacing(8)
        grid.setVerticalSpacing(6)

        # Connection inputs
        self.host_input = QLineEdit("ci009ngppad-010")
        self.host_input.setPlaceholderText("Host")

        self.port_input = QSpinBox()
        self.port_input.setRange(1, 65535)
        self.port_input.setValue(12345)

        self.connect_btn = QPushButton("Connect")

        self.status_label = QLabel("Disconnected")
        self.status_label.setStyleSheet("color: #B00020; font-weight: 600;")

        # Preset action dropdown
        self.preset_combo = QComboBox()
        self.preset_combo.addItem(CUSTOM_OPTION)
        for name in PRESET_HEX.keys():
            self.preset_combo.addItem(name)

        # Label field (required when Custom preset selected)
        self.label_input = QLineEdit("")
        self.label_input.setPlaceholderText("Required label")

        # Row 0: host/port/connect/status
        grid.addWidget(QLabel("Host"), 0, 0)
        grid.addWidget(self.host_input, 0, 1, 1, 3)
        grid.addWidget(QLabel("Port"), 0, 4)
        grid.addWidget(self.port_input, 0, 5)
        grid.addWidget(self.connect_btn, 0, 6)
        grid.addWidget(QLabel("Status"), 0, 7)
        grid.addWidget(self.status_label, 0, 8)

        # Row 1: preset + label
        grid.addWidget(QLabel("Preset"), 1, 0)
        grid.addWidget(self.preset_combo, 1, 1, 1, 3)
        grid.addWidget(QLabel("Label"), 1, 4)
        grid.addWidget(self.label_input, 1, 5, 1, 4)

        # Hex message box (editable)
        self.hex_label = QLabel("Hex Message")
        self.hex_edit = QPlainTextEdit()
        self.hex_edit.setPlaceholderText("Type raw hex bytes here. Example: 0F31310E")
        self.hex_edit.setMinimumHeight(140)

        self.hex_error_label = QLabel("")
        self.hex_error_label.setStyleSheet("color: #B00020;")

        # Send row
        send_row = QHBoxLayout()
        send_row.addStretch(1)
        self.send_btn = QPushButton("Send")
        send_row.addWidget(self.send_btn)

        # Bytes preview box (read-only)
        self.bytes_label = QLabel("Bytes Message")
        self.bytes_preview_edit = QPlainTextEdit()
        self.bytes_preview_edit.setReadOnly(True)
        self.bytes_preview_edit.setMinimumHeight(140)

        # History area (read-only, monospace)
        self.history_label = QLabel("History (newest at top)")
        self.history_edit = QPlainTextEdit()
        self.history_edit.setReadOnly(True)
        self.history_edit.setMinimumHeight(300)
        self.history_edit.setWordWrapMode(QTextOption.NoWrap)

        mono = QFont("Menlo")
        mono.setStyleHint(QFont.Monospace)
        self.history_edit.setFont(mono)

        # Assemble layout
        root_layout.addLayout(grid)
        root_layout.addWidget(self.hex_label)
        root_layout.addWidget(self.hex_edit)
        root_layout.addWidget(self.hex_error_label)
        root_layout.addLayout(send_row)
        root_layout.addWidget(self.bytes_label)
        root_layout.addWidget(self.bytes_preview_edit)
        root_layout.addWidget(self.history_label)
        root_layout.addWidget(self.history_edit)

        self.setCentralWidget(root)

        # Initialize UI rules for presets/labels
        self._apply_preset_selection(self.preset_combo.currentText())

    def _build_worker(self) -> None:
        """Create worker + thread and move worker into background thread."""
        self.worker_thread = QThread(self)
        self.worker = TcpWorker()
        self.worker.moveToThread(self.worker_thread)
        self.worker_thread.start()

    def _wire_events(self) -> None:
        """Connect Qt signals and slots."""
        # UI events
        self.connect_btn.clicked.connect(self._on_connect_toggle)
        self.send_btn.clicked.connect(self._on_send_clicked)
        self.hex_edit.textChanged.connect(self._on_hex_text_changed)
        self.preset_combo.currentTextChanged.connect(self._apply_preset_selection)
        self.label_input.textChanged.connect(lambda: self._refresh_send_button_state())

        # UI -> worker requests
        self.request_connect.connect(self.worker.connect_to_host)
        self.request_disconnect.connect(self.worker.disconnect_from_host)
        self.request_send.connect(self.worker.send_payload)

        # Worker -> UI updates
        self.worker.connected.connect(self._on_connected)
        self.worker.disconnected.connect(self._on_disconnected)
        self.worker.error.connect(self._on_worker_error)
        self.worker.send_result.connect(self._on_send_result)
        self.worker.send_error.connect(self._on_send_error)

    # --------------------------- Qt lifecycle ---------------------------

    def closeEvent(self, event) -> None:  # type: ignore[override]
        """Ensure we disconnect cleanly and stop the worker thread on close."""
        if self.worker.is_connected:
            self.request_disconnect.emit()
        self.worker_thread.quit()
        self.worker_thread.wait(1500)
        super().closeEvent(event)

    # --------------------------- UI state helpers ---------------------------

    def _set_connected_ui(self, connected: bool) -> None:
        """Update connect button + status label based on connection state."""
        self._is_connected = connected
        self.connect_btn.setText("Disconnect" if connected else "Connect")
        self.status_label.setText("Connected" if connected else "Disconnected")
        color = "#1E7D32" if connected else "#B00020"
        self.status_label.setStyleSheet(f"color: {color}; font-weight: 600;")
        self._refresh_send_button_state()

    def _current_label(self) -> str:
        """
        Determine the label that will be written into history/YAML:
        - Preset selected -> label is preset name
        - Custom selected -> label must come from label_input
        """
        preset = self.preset_combo.currentText()
        if preset != CUSTOM_OPTION:
            return preset
        return self.label_input.text().strip()

    def _refresh_send_button_state(self) -> None:
        """
        Enable Send only if:
          - connected
          - hex is valid
          - label requirements satisfied (custom requires a label)
        """
        label_ok = bool(self._current_label())
        self.send_btn.setEnabled(self._is_connected and self._last_hex_result.is_valid and label_ok)

    def _append_history_block(self, block: str) -> None:
        """Insert newest at top, then refresh history textbox."""
        self._history_blocks.insert(0, block)
        self.history_edit.setPlainText("\n\n".join(self._history_blocks))

    def _write_yaml_record(
        self,
        *,
        kind: str,
        label: str,
        sent: bytes,
        received: bytes,
        note: str,
        error: Optional[str] = None,
    ) -> None:
        """
        Persist a record to YAML so the program (or other tools) can parse it later.
        """
        record = {
            "ts": timestamp_now(),
            "kind": kind,  # "send_result" or "send_error"
            "label": label,
            "host": self._connected_host,
            "port": self._connected_port,
            "sent_hex": bytes_to_hex_spaced(sent),
            "sent_preview": bytes_preview(sent),
            "recv_hex": bytes_to_hex_spaced(received),
            "recv_preview": bytes_preview(received),
            "note": note,
            "error": error,
        }
        append_history_yaml(record)

    # --------------------------- Preset behavior ---------------------------

    @Slot(str)
    def _apply_preset_selection(self, preset_name: str) -> None:
        """
        When user selects a preset:
        - Preset: label is forced to preset name and label box is disabled
        - Custom: label box is cleared + enabled and REQUIRED to send
        """
        if preset_name == CUSTOM_OPTION:
            # Custom: user must provide a label, so clear anything old (prevents "Cancel" labeling)
            self.label_input.setEnabled(True)
            self.label_input.setText("")  # <-- important fix
            self.label_input.setPlaceholderText("Required label")

            # Don't overwrite hex for Custom (user may be composing something)
            # (leave hex_edit as-is)
        else:
            # Preset: force the label to match the preset and prevent edits
            self.label_input.setText(preset_name)
            self.label_input.setEnabled(False)
            self.label_input.setPlaceholderText("Required label")

            # Autofill hex if we have it (otherwise leave it as-is)
            preset_hex = PRESET_HEX.get(preset_name, "")
            if preset_hex != "":
                self.hex_edit.setPlainText(preset_hex)

        self._refresh_send_button_state()

    # --------------------------- UI event handlers ---------------------------

    @Slot()
    def _on_connect_toggle(self) -> None:
        """Connect or disconnect depending on current state."""
        if self._is_connected:
            self.request_disconnect.emit()
            return

        host = self.host_input.text().strip()
        if not host:
            QMessageBox.warning(self, "Invalid host", "Host is required.")
            return

        port = int(self.port_input.value())
        self.request_connect.emit(host, port)

    @Slot()
    def _on_send_clicked(self) -> None:
        """
        User clicked Send:
          - Validate label and hex (UI already enforces it, but we keep checks)
          - Disable Send during the request
          - Ask worker thread to send bytes and read response
        """
        if not self._is_connected:
            return
        if not self._last_hex_result.is_valid:
            return

        label = self._current_label()
        if not label:
            QMessageBox.warning(self, "Missing label", "Custom sends require a label.")
            return

        self.send_btn.setEnabled(False)
        self.request_send.emit(self._last_hex_result.payload, label)

    @Slot()
    def _on_hex_text_changed(self) -> None:
        """Live-validate hex and update the bytes preview box."""
        self._last_hex_result = parse_hex_input(self.hex_edit.toPlainText())

        if self._last_hex_result.is_valid:
            self.hex_error_label.setText("")
            self.bytes_preview_edit.setPlainText(bytes_preview(self._last_hex_result.payload))
        else:
            self.hex_error_label.setText(self._last_hex_result.error)
            self.bytes_preview_edit.setPlainText("Invalid hex input.")

        self._refresh_send_button_state()

    # --------------------------- Worker callbacks ---------------------------

    @Slot(str, int)
    def _on_connected(self, host: str, port: int) -> None:
        """Worker successfully connected."""
        self._connected_host = host
        self._connected_port = port
        self._set_connected_ui(True)

    @Slot(str)
    def _on_disconnected(self, _reason: str) -> None:
        """Worker disconnected (manual or peer closed)."""
        self._set_connected_ui(False)

    @Slot(str)
    def _on_worker_error(self, message: str) -> None:
        """General worker errors not tied to a specific send."""
        block = f"[{timestamp_now()}] ERROR\nMessage: {message}"
        self._append_history_block(block)
        self._refresh_send_button_state()

    @Slot(str, bytes, bytes, str)
    def _on_send_result(self, label: str, sent: bytes, received: bytes, note: str) -> None:
        """Worker sent bytes and received a response."""
        sent_hex = bytes_to_hex_spaced(sent)
        sent_preview = bytes_preview(sent)

        recv_hex = bytes_to_hex_spaced(received)
        recv_preview = bytes_preview(received)

        note_line = f"Note: {note}\n" if note else ""
        block = (
            f"[{timestamp_now()}]\n"
            f"Label: {label}\n"
            f"Host: {self._connected_host}:{self._connected_port}\n"
            f"→ SENT\n"
            f"Sent Hex: {sent_hex}\n"
            f"Sent Bytes Preview: {sent_preview}\n"
            f"← RECV\n"
            f"Received Hex: {recv_hex}\n"
            f"Received Bytes Preview: {recv_preview}\n"
            f"{note_line}"
        ).rstrip()

        # Update UI history
        self._append_history_block(block)

        # Persist to YAML
        self._write_yaml_record(
            kind="send_result",
            label=label,
            sent=sent,
            received=received,
            note=note,
            error=None,
        )

        self._refresh_send_button_state()

    @Slot(str, bytes, str)
    def _on_send_error(self, label: str, sent: bytes, message: str) -> None:
        """Worker had an error for a specific send (timeout/no response/etc)."""
        sent_hex = bytes_to_hex_spaced(sent)
        sent_preview = bytes_preview(sent)

        block = (
            f"[{timestamp_now()}] ERROR\n"
            f"Label: {label}\n"
            f"Host: {self._connected_host}:{self._connected_port}\n"
            f"→ SENT\n"
            f"Sent Hex: {sent_hex}\n"
            f"Sent Bytes Preview: {sent_preview}\n"
            f"Message: {message}"
        )

        # Update UI history
        self._append_history_block(block)

        # Persist to YAML
        self._write_yaml_record(
            kind="send_error",
            label=label,
            sent=sent,
            received=b"",
            note="",
            error=message,
        )

        self._refresh_send_button_state()


# --------------------------------------------------------------------------------------
# App entry point
# --------------------------------------------------------------------------------------
def main() -> int:
    app = QApplication(sys.argv)

    # Optional global app icon (same directory as the script)
    icon_path = Path(__file__).resolve().parent / "icon.jpg"
    if icon_path.exists():
        app.setWindowIcon(QIcon(str(icon_path)))

    window = MainWindow()
    window.show()
    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())
