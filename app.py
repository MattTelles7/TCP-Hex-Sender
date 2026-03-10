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
# Hex parsing helpers
# --------------------------------------------------------------------------------------
HEX_CLEAN_RE = re.compile(r"\s+", re.MULTILINE)  # remove whitespace
HEX_PREFIX_RE = re.compile(r"0x", re.IGNORECASE)  # remove optional 0x prefixes

# --------------------------------------------------------------------------------------
# Connection + read timing
# --------------------------------------------------------------------------------------
CONNECT_TIMEOUT_S = 3.0

# "Response read" timing (after you Send)
FIRST_BYTE_TIMEOUT_S = 5.0  # wait this long for the first byte of a response
RAW_IDLE_TIMEOUT_S = 1.50  # once bytes start flowing, stop after this idle period
RAW_MAX_TOTAL_TIMEOUT_S = 15.0  # hard cap for a single read cycle

# "Drain read" timing (before you Send)
# This prevents stale/late bytes from being mislabeled as the next command’s response.
DRAIN_FIRST_BYTE_TIMEOUT_S = 0.10
DRAIN_IDLE_TIMEOUT_S = 0.10
DRAIN_MAX_TOTAL_TIMEOUT_S = 0.50

# --------------------------------------------------------------------------------------
# Protocol-ish behavior
# Many pinpad / host-term protocols use ACK/NAK/EOT and STX...ETX+LRC framing.
#   ACK = 0x06
#   NAK = 0x15
#   EOT = 0x04
#   STX = 0x02
#   ETX = 0x03
#
# Requirement: if we receive any message that DOES NOT start with 0x06, 0x15, or 0x04,
# immediately send 0x06 back.
#
# IMPORTANT: The "right" ACK behavior is usually "ACK each complete frame".
# So we do per-frame ACK for STX...ETX+LRC frames, and a single ACK for unknown-leading bytes.
# --------------------------------------------------------------------------------------
ACK_BYTE = b"\x06"
NO_ACK_PREFIXES = {0x06, 0x15, 0x04}
STX = 0x02
ETX = 0x03

# --------------------------------------------------------------------------------------
# History persistence
# We append YAML docs (---) because it's easy to append and easy to parse with YAML load_all().
# We write YAML ourselves (no external dependency) using minimal escaping.
# --------------------------------------------------------------------------------------
HISTORY_PATH = Path(__file__).resolve().parent / "tcp_hex_history.yaml"

# --------------------------------------------------------------------------------------
# Presets (YOU should replace these hex strings with your real commands)
# --------------------------------------------------------------------------------------
PRESET_HEX: dict[str, str] = {
    "Ping": "0F31310E",
    "Cancel": "0237320306",
    "Get Card": "",  # TODO
    "Start Transaction": "",  # TODO
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
class DeviceReadResult:
    raw_wire_bytes: bytes  # all bytes received on the wire in this read cycle
    leftover_buffer: bytes  # partial bytes we couldn't frame yet (kept for later)
    note: str
    peer_closed: bool
    ack_sent_count: int
    framed_count: int  # how many STX...ETX+LRC frames were recognized


class ConnectionClosedError(Exception):
    """Raised when the remote peer closes the TCP connection cleanly."""
    pass


# --------------------------------------------------------------------------------------
# Formatting helpers
# --------------------------------------------------------------------------------------
def timestamp_now() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]


def bytes_to_hex_spaced(data: bytes) -> str:
    if not data:
        return "(empty)"
    return " ".join(f"{b:02X}" for b in data)


def bytes_preview(data: bytes) -> str:
    """
    Display printable ASCII as characters, everything else as <0xNN>.
    """
    if not data:
        return "(empty)"
    out: list[str] = []
    for b in data:
        if 0x20 <= b <= 0x7E:
            out.append(chr(b))
        else:
            out.append(f"<0x{b:02X}>")
    return "".join(out)


# --------------------------------------------------------------------------------------
# Hex parsing
# --------------------------------------------------------------------------------------
def parse_hex_input(raw_text: str) -> HexParseResult:
    cleaned = HEX_CLEAN_RE.sub("", raw_text)
    cleaned = HEX_PREFIX_RE.sub("", cleaned)

    if cleaned == "":
        return HexParseResult(True, "", b"", "(empty)")

    if re.search(r"[^0-9A-Fa-f]", cleaned):
        return HexParseResult(False, "Invalid hex: non-hex character found.", b"", "")

    if len(cleaned) % 2 != 0:
        return HexParseResult(False, "Invalid hex: odd number of hex digits.", b"", "")

    try:
        payload = bytes.fromhex(cleaned)
    except ValueError:
        return HexParseResult(False, "Invalid hex input.", b"", "")

    return HexParseResult(True, "", payload, bytes_to_hex_spaced(payload))


# --------------------------------------------------------------------------------------
# YAML writer (minimal, dependency-free)
# --------------------------------------------------------------------------------------
def _yaml_escape_string(value: str) -> str:
    value = value.replace("\\", "\\\\").replace('"', '\\"')
    value = value.replace("\r", "\\r").replace("\n", "\\n")
    return f'"{value}"'


def _yaml_scalar(value: Any) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return str(value)
    return _yaml_escape_string(str(value))


def append_history_yaml(record: dict[str, Any]) -> None:
    HISTORY_PATH.parent.mkdir(parents=True, exist_ok=True)
    with HISTORY_PATH.open("a", encoding="utf-8") as f:
        f.write("---\n")
        for key, val in record.items():
            f.write(f"{key}: {_yaml_scalar(val)}\n")


# --------------------------------------------------------------------------------------
# Framing helpers
# --------------------------------------------------------------------------------------
def _extract_units_from_buffer(buffer: bytearray) -> tuple[list[bytes], int]:
    """
    Pull as many complete "units" out of the buffer as possible.

    Units we recognize:
      - Single-byte control messages: ACK (06), NAK (15), EOT (04)
      - Framed messages: STX (02) ... ETX (03) + LRC (1 byte)

    For unknown leading bytes, we don't know framing, so we only consume 1 byte
    (and we handle ACK policy elsewhere).
    """
    units: list[bytes] = []
    framed_count = 0

    while buffer:
        b0 = buffer[0]

        # Single-byte control codes
        if b0 in (0x06, 0x15, 0x04):
            units.append(bytes(buffer[:1]))
            del buffer[:1]
            continue

        # STX framed message: STX ... ETX + LRC
        if b0 == STX:
            etx_idx = buffer.find(bytes([ETX]), 1)
            if etx_idx == -1:
                break  # need more bytes
            if len(buffer) < etx_idx + 2:
                break  # have ETX but not LRC yet
            frame = bytes(buffer[: etx_idx + 2])  # include ETX and 1-byte LRC
            del buffer[: etx_idx + 2]
            units.append(frame)
            framed_count += 1
            continue

        # Unknown: consume 1 byte so we don't hold forever
        units.append(bytes(buffer[:1]))
        del buffer[:1]

    return units, framed_count


def read_device_messages(
    sock: socket.socket,
    initial_buffer: bytes,
    *,
    first_byte_timeout_s: float,
    idle_timeout_s: float,
    max_total_timeout_s: float,
    auto_ack: bool,
) -> DeviceReadResult:
    """
    Device-friendly read loop with basic framing + ACK behavior.

    Key goals:
      - Avoid "random partial reads" by recognizing STX...ETX+LRC frames.
      - ACK each complete frame that doesn't start with 06/15/04.
      - Avoid mislabeling by returning leftover partial bytes.
    """
    buffer = bytearray(initial_buffer)  # bytes not yet framed
    wire = bytearray(initial_buffer)  # all bytes received on the wire this cycle
    peer_closed = False
    ack_sent_count = 0
    framed_total = 0
    unknown_ack_sent = False

    start = time.monotonic()
    stop_reason = ""

    # Wait for first byte if we have nothing buffered
    if not buffer:
        ready, _, _ = select.select([sock], [], [], first_byte_timeout_s)
        if not ready:
            return DeviceReadResult(
                raw_wire_bytes=b"",
                leftover_buffer=b"",
                note=f"No bytes received within first-byte timeout ({first_byte_timeout_s:.2f}s).",
                peer_closed=False,
                ack_sent_count=0,
                framed_count=0,
            )

    # Main read loop: keep receiving until idle or max total timeout
    while True:
        elapsed = time.monotonic() - start
        remaining = max_total_timeout_s - elapsed
        if remaining <= 0:
            stop_reason = f"max-total timeout ({max_total_timeout_s:.2f}s)"
            break

        sock.settimeout(min(idle_timeout_s, remaining))
        try:
            chunk = sock.recv(4096)
            if chunk == b"":
                peer_closed = True
                stop_reason = "peer closed"
                break

            wire.extend(chunk)
            buffer.extend(chunk)

            # Each time we get more bytes, try to extract complete units
            units, framed_count = _extract_units_from_buffer(buffer)
            framed_total += framed_count

            if auto_ack:
                for unit in units:
                    # ACK policy:
                    # - If unit starts with 06/15/04 -> never ACK
                    # - If it's a framed STX unit -> ACK every frame
                    # - If unknown 1-byte unit -> ACK only once per read cycle to avoid spamming
                    first = unit[0] if unit else None
                    if first is None:
                        continue
                    if first in NO_ACK_PREFIXES:
                        continue
                    if first == STX:
                        try:
                            sock.sendall(ACK_BYTE)
                            ack_sent_count += 1
                        except OSError:
                            pass
                    else:
                        if not unknown_ack_sent:
                            try:
                                sock.sendall(ACK_BYTE)
                                ack_sent_count += 1
                                unknown_ack_sent = True
                            except OSError:
                                pass

        except socket.timeout:
            stop_reason = f"idle timeout ({int(idle_timeout_s * 1000)} ms)"
            break

    leftover_hex = bytes_to_hex_spaced(bytes(buffer)) if buffer else "(none)"
    note = (
        f"Read stop={stop_reason}, wire_bytes={len(wire)}, "
        f"framed={framed_total}, ack_sent={ack_sent_count}, "
        f"leftover={leftover_hex}."
    )

    return DeviceReadResult(
        raw_wire_bytes=bytes(wire),
        leftover_buffer=bytes(buffer),
        note=note,
        peer_closed=peer_closed,
        ack_sent_count=ack_sent_count,
        framed_count=framed_total,
    )


# --------------------------------------------------------------------------------------
# Worker thread (all socket I/O lives here)
# --------------------------------------------------------------------------------------
class TcpWorker(QObject):
    connected = Signal(str, int)  # host, port
    disconnected = Signal(str)  # reason

    # Send result for a labeled command
    send_result = Signal(str, bytes, bytes, str)  # label, sent, received, note
    send_error = Signal(str, bytes, str)  # label, sent, error message

    # Any bytes that arrived BEFORE we sent a command (drain / unsolicited)
    unsolicited = Signal(bytes, str)  # bytes, note

    # General errors
    error = Signal(str)

    def __init__(self) -> None:
        super().__init__()
        self._sock: Optional[socket.socket] = None
        self._host = ""
        self._port = 0

        # Buffer for partial frames between reads
        self._recv_buffer = b""

    @property
    def is_connected(self) -> bool:
        return self._sock is not None

    @Slot(str, int)
    def connect_to_host(self, host: str, port: int) -> None:
        if self._sock is not None:
            self.disconnected.emit("Already connected. Disconnect first.")
            return

        try:
            addr_infos = socket.getaddrinfo(host, port, socket.AF_UNSPEC, socket.SOCK_STREAM)
        except OSError as exc:
            self.error.emit(f"Connect failed: {exc}")
            return

        sock: Optional[socket.socket] = None
        connect_error: Optional[Exception] = None

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

    def _drain_unsolicited_bytes(self) -> None:
        """
        Drain anything already queued on the socket so it doesn't get attributed to the next Send.

        If we drain bytes, we emit them as "unsolicited" and keep any partial-frame leftovers.
        """
        if self._sock is None:
            return

        result = read_device_messages(
            self._sock,
            self._recv_buffer,
            first_byte_timeout_s=DRAIN_FIRST_BYTE_TIMEOUT_S,
            idle_timeout_s=DRAIN_IDLE_TIMEOUT_S,
            max_total_timeout_s=DRAIN_MAX_TOTAL_TIMEOUT_S,
            auto_ack=True,
        )

        self._recv_buffer = result.leftover_buffer

        if result.raw_wire_bytes:
            self.unsolicited.emit(result.raw_wire_bytes, f"Drain: {result.note}")

    @Slot(bytes, str)
    def send_payload(self, payload: bytes, label: str) -> None:
        if self._sock is None:
            self.send_error.emit(label, payload, "Not connected.")
            return

        try:
            # 1) Drain any leftover/late bytes BEFORE sending
            self._drain_unsolicited_bytes()

            # 2) WRITE: send request bytes
            self._sock.sendall(payload)

            # 3) READ: capture response frames, send ACKs as needed
            result = read_device_messages(
                self._sock,
                self._recv_buffer,
                first_byte_timeout_s=FIRST_BYTE_TIMEOUT_S,
                idle_timeout_s=RAW_IDLE_TIMEOUT_S,
                max_total_timeout_s=RAW_MAX_TOTAL_TIMEOUT_S,
                auto_ack=True,
            )

            # Keep partial bytes for next time
            self._recv_buffer = result.leftover_buffer

            if result.raw_wire_bytes:
                self.send_result.emit(label, payload, result.raw_wire_bytes, result.note)
            else:
                self.send_error.emit(label, payload, result.note)

            if result.peer_closed:
                try:
                    self._sock.close()
                except OSError:
                    pass
                self._sock = None
                self._recv_buffer = b""
                self.disconnected.emit("Peer closed the connection.")

        except (OSError, ConnectionClosedError) as exc:
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
    request_connect = Signal(str, int)
    request_disconnect = Signal()
    request_send = Signal(bytes, str)  # payload, label

    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("TCP Hex Sender")

        icon_path = Path(__file__).resolve().parent / "icon.png"
        if icon_path.exists():
            self.setWindowIcon(QIcon(str(icon_path)))

        self.resize(1000, 820)

        self._is_connected = False
        self._connected_host = ""
        self._connected_port = 0
        self._last_hex_result = parse_hex_input("")
        self._history_blocks: list[str] = []

        # Prevents our "preset tamper detection" from triggering when we programmatically set hex.
        self._suppress_hex_autoswitch = False

        self._build_ui()
        self._build_worker()
        self._wire_events()
        self._refresh_send_button_state()

    # ----------------------- UI build -----------------------

    def _build_ui(self) -> None:
        root = QWidget()
        layout = QVBoxLayout(root)
        layout.setContentsMargins(10, 10, 10, 10)
        layout.setSpacing(8)

        grid = QGridLayout()
        grid.setHorizontalSpacing(8)
        grid.setVerticalSpacing(6)

        self.host_input = QLineEdit("ci009ngppad-010")
        self.host_input.setPlaceholderText("Host")

        self.port_input = QSpinBox()
        self.port_input.setRange(1, 65535)
        self.port_input.setValue(12345)

        self.connect_btn = QPushButton("Connect")

        self.status_label = QLabel("Disconnected")
        self.status_label.setStyleSheet("color: #B00020; font-weight: 600;")

        self.preset_combo = QComboBox()
        self.preset_combo.addItem(CUSTOM_OPTION)
        for name in PRESET_HEX.keys():
            self.preset_combo.addItem(name)

        # Label is REQUIRED only for Custom, but we keep a single placeholder text.
        self.label_input = QLineEdit("")
        self.label_input.setPlaceholderText("Required label")

        # Row 0
        grid.addWidget(QLabel("Host"), 0, 0)
        grid.addWidget(self.host_input, 0, 1, 1, 3)
        grid.addWidget(QLabel("Port"), 0, 4)
        grid.addWidget(self.port_input, 0, 5)
        grid.addWidget(self.connect_btn, 0, 6)
        grid.addWidget(QLabel("Status"), 0, 7)
        grid.addWidget(self.status_label, 0, 8)

        # Row 1
        grid.addWidget(QLabel("Preset"), 1, 0)
        grid.addWidget(self.preset_combo, 1, 1, 1, 3)
        grid.addWidget(QLabel("Label"), 1, 4)
        grid.addWidget(self.label_input, 1, 5, 1, 4)

        self.hex_label = QLabel("Hex Message")
        self.hex_edit = QPlainTextEdit()
        self.hex_edit.setPlaceholderText("Type raw hex bytes here. Example: 0F31310E")
        self.hex_edit.setMinimumHeight(140)

        self.hex_error_label = QLabel("")
        self.hex_error_label.setStyleSheet("color: #B00020;")

        send_row = QHBoxLayout()
        send_row.addStretch(1)
        self.send_btn = QPushButton("Send")
        send_row.addWidget(self.send_btn)

        self.bytes_label = QLabel("Bytes Message")
        self.bytes_preview_edit = QPlainTextEdit()
        self.bytes_preview_edit.setReadOnly(True)
        self.bytes_preview_edit.setMinimumHeight(140)

        self.history_label = QLabel("History (newest at top)")
        self.history_edit = QPlainTextEdit()
        self.history_edit.setReadOnly(True)
        self.history_edit.setMinimumHeight(320)
        self.history_edit.setWordWrapMode(QTextOption.NoWrap)

        mono = QFont("Menlo")
        mono.setStyleHint(QFont.Monospace)
        self.history_edit.setFont(mono)

        layout.addLayout(grid)
        layout.addWidget(self.hex_label)
        layout.addWidget(self.hex_edit)
        layout.addWidget(self.hex_error_label)
        layout.addLayout(send_row)
        layout.addWidget(self.bytes_label)
        layout.addWidget(self.bytes_preview_edit)
        layout.addWidget(self.history_label)
        layout.addWidget(self.history_edit)

        self.setCentralWidget(root)

        # Apply initial preset rules
        self._apply_preset_selection(self.preset_combo.currentText())

    def _build_worker(self) -> None:
        self.worker_thread = QThread(self)
        self.worker = TcpWorker()
        self.worker.moveToThread(self.worker_thread)
        self.worker_thread.start()

    def _wire_events(self) -> None:
        self.connect_btn.clicked.connect(self._on_connect_toggle)
        self.send_btn.clicked.connect(self._on_send_clicked)

        # IMPORTANT: hex text change does parsing + (new) preset tamper detection
        self.hex_edit.textChanged.connect(self._on_hex_text_changed)

        self.preset_combo.currentTextChanged.connect(self._apply_preset_selection)
        self.label_input.textChanged.connect(lambda: self._refresh_send_button_state())

        self.request_connect.connect(self.worker.connect_to_host)
        self.request_disconnect.connect(self.worker.disconnect_from_host)
        self.request_send.connect(self.worker.send_payload)

        self.worker.connected.connect(self._on_connected)
        self.worker.disconnected.connect(self._on_disconnected)
        self.worker.error.connect(self._on_worker_error)
        self.worker.unsolicited.connect(self._on_unsolicited)
        self.worker.send_result.connect(self._on_send_result)
        self.worker.send_error.connect(self._on_send_error)

    def closeEvent(self, event) -> None:  # type: ignore[override]
        if self.worker.is_connected:
            self.request_disconnect.emit()
        self.worker_thread.quit()
        self.worker_thread.wait(1500)
        super().closeEvent(event)

    # ----------------------- State helpers -----------------------

    def _set_connected_ui(self, connected: bool) -> None:
        self._is_connected = connected
        self.connect_btn.setText("Disconnect" if connected else "Connect")
        self.status_label.setText("Connected" if connected else "Disconnected")
        color = "#1E7D32" if connected else "#B00020"
        self.status_label.setStyleSheet(f"color: {color}; font-weight: 600;")
        self._refresh_send_button_state()

    def _current_label(self) -> str:
        preset = self.preset_combo.currentText()
        if preset != CUSTOM_OPTION:
            return preset
        return self.label_input.text().strip()

    def _refresh_send_button_state(self) -> None:
        label_ok = bool(self._current_label())
        self.send_btn.setEnabled(self._is_connected and self._last_hex_result.is_valid and label_ok)

    def _append_history_block(self, block: str) -> None:
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
        record = {
            "ts": timestamp_now(),
            "kind": kind,  # "send_result" | "send_error" | "unsolicited"
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

    def _clean_hex_for_compare(self, text: str) -> str:
        """
        Normalize hex so spaces/newlines/0x prefixes do not matter during comparisons.
        """
        cleaned = HEX_CLEAN_RE.sub("", text)
        cleaned = HEX_PREFIX_RE.sub("", cleaned)
        return cleaned.lower()

    # ----------------------- Presets -----------------------

    @Slot(str)
    def _apply_preset_selection(self, preset_name: str) -> None:
        """
        Preset behavior:
          - Preset selected: label forced to preset name, label box disabled, hex can autofill.
          - Custom selected: label cleared and enabled; REQUIRED before Send is enabled.
        """
        if preset_name == CUSTOM_OPTION:
            self.label_input.setEnabled(True)
            self.label_input.setText("")  # prevent accidental carry-over labeling
        else:
            self.label_input.setText(preset_name)
            self.label_input.setEnabled(False)

            preset_hex = PRESET_HEX.get(preset_name, "")
            if preset_hex:
                # Prevent "hex changed" logic from immediately flipping us to Custom
                self._suppress_hex_autoswitch = True
                try:
                    self.hex_edit.setPlainText(preset_hex)
                finally:
                    self._suppress_hex_autoswitch = False

        self._refresh_send_button_state()

    # ----------------------- UI handlers -----------------------

    @Slot()
    def _on_connect_toggle(self) -> None:
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
        if not self._is_connected:
            return
        if not self._last_hex_result.is_valid:
            return

        label = self._current_label()
        if not label:
            QMessageBox.warning(self, "Missing label", "Custom sends require a label.")
            return

        # Disable until we get a response/error back
        self.send_btn.setEnabled(False)
        self.request_send.emit(self._last_hex_result.payload, label)

    @Slot()
    def _on_hex_text_changed(self) -> None:
        """
        Hex box changed:
          1) Parse + update bytes preview + validation
          2) If a preset is selected and user edits hex away from that preset, auto-switch to Custom
             and blank the label (so we never log Ping with Cancel bytes, etc.).
        """
        # Always parse/update preview + validation first
        self._last_hex_result = parse_hex_input(self.hex_edit.toPlainText())

        if self._last_hex_result.is_valid:
            self.hex_error_label.setText("")
            self.bytes_preview_edit.setPlainText(bytes_preview(self._last_hex_result.payload))
        else:
            self.hex_error_label.setText(self._last_hex_result.error)
            self.bytes_preview_edit.setPlainText("Invalid hex input.")

        # If we set hex programmatically (preset autofill), don't autoswitch
        if self._suppress_hex_autoswitch:
            self._refresh_send_button_state()
            return

        # If a preset is selected and hex no longer matches preset hex, force Custom + blank label
        preset = self.preset_combo.currentText()
        if preset != CUSTOM_OPTION:
            preset_hex = PRESET_HEX.get(preset, "")
            current_clean = self._clean_hex_for_compare(self.hex_edit.toPlainText())
            preset_clean = self._clean_hex_for_compare(preset_hex)

            if current_clean != preset_clean:
                # This triggers _apply_preset_selection(CUSTOM_OPTION), which clears/enables label.
                self.preset_combo.setCurrentText(CUSTOM_OPTION)

        self._refresh_send_button_state()

    # ----------------------- Worker callbacks -----------------------

    @Slot(str, int)
    def _on_connected(self, host: str, port: int) -> None:
        self._connected_host = host
        self._connected_port = port
        self._set_connected_ui(True)

    @Slot(str)
    def _on_disconnected(self, _reason: str) -> None:
        self._set_connected_ui(False)

    @Slot(str)
    def _on_worker_error(self, message: str) -> None:
        block = f"[{timestamp_now()}] ERROR\nMessage: {message}"
        self._append_history_block(block)
        self._refresh_send_button_state()

    @Slot(bytes, str)
    def _on_unsolicited(self, received: bytes, note: str) -> None:
        """
        Bytes that arrived before we sent a command. Logging these separately prevents
        your next send from "randomly" getting attributed the wrong response.
        """
        block = (
            f"[{timestamp_now()}]\n"
            f"Label: Unsolicited / Drained\n"
            f"Host: {self._connected_host}:{self._connected_port}\n"
            f"← RECV\n"
            f"Received Hex: {bytes_to_hex_spaced(received)}\n"
            f"Received Bytes Preview: {bytes_preview(received)}\n"
            f"Note: {note}"
        )
        self._append_history_block(block)

        self._write_yaml_record(
            kind="unsolicited",
            label="Unsolicited",
            sent=b"",
            received=received,
            note=note,
            error=None,
        )

    @Slot(str, bytes, bytes, str)
    def _on_send_result(self, label: str, sent: bytes, received: bytes, note: str) -> None:
        block = (
            f"[{timestamp_now()}]\n"
            f"Label: {label}\n"
            f"Host: {self._connected_host}:{self._connected_port}\n"
            f"→ SENT\n"
            f"Sent Hex: {bytes_to_hex_spaced(sent)}\n"
            f"Sent Bytes Preview: {bytes_preview(sent)}\n"
            f"← RECV\n"
            f"Received Hex: {bytes_to_hex_spaced(received)}\n"
            f"Received Bytes Preview: {bytes_preview(received)}\n"
            f"Note: {note}"
        )
        self._append_history_block(block)

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
        block = (
            f"[{timestamp_now()}] ERROR\n"
            f"Label: {label}\n"
            f"Host: {self._connected_host}:{self._connected_port}\n"
            f"→ SENT\n"
            f"Sent Hex: {bytes_to_hex_spaced(sent)}\n"
            f"Sent Bytes Preview: {bytes_preview(sent)}\n"
            f"Message: {message}"
        )
        self._append_history_block(block)

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
# Entrypoint
# --------------------------------------------------------------------------------------
def main() -> int:
    app = QApplication(sys.argv)

    icon_path = Path(__file__).resolve().parent / "icon.png"
    if icon_path.exists():
        app.setWindowIcon(QIcon(str(icon_path)))

    window = MainWindow()
    window.show()
    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())
