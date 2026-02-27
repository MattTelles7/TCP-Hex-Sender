import re
import select
import socket
import sys
from dataclasses import dataclass
from datetime import datetime
from typing import Optional

from PySide6.QtCore import QObject, QThread, Signal, Slot
from PySide6.QtGui import QFont, QTextOption
from PySide6.QtWidgets import (
    QApplication,
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

HEX_CLEAN_RE = re.compile(r"\s+", re.MULTILINE)
HEX_PREFIX_RE = re.compile(r"0x", re.IGNORECASE)
CONNECT_TIMEOUT_S = 3.0

# Device-style read behavior:
# - Wait up to FIRST_BYTE_TIMEOUT_S for the first response byte.
# - Then keep reading until no new bytes arrive for RAW_IDLE_TIMEOUT_S.
FIRST_BYTE_TIMEOUT_S = 5.0
RAW_IDLE_TIMEOUT_S = 0.5


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


class ConnectionClosedError(Exception):
    pass


def timestamp_now() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]


def bytes_to_hex_spaced(data: bytes) -> str:
    if not data:
        return "(empty)"
    return " ".join(f"{byte:02X}" for byte in data)


def bytes_preview(data: bytes) -> str:
    if not data:
        return "(empty)"

    out = []
    for byte in data:
        if 0x20 <= byte <= 0x7E:
            out.append(chr(byte))
        else:
            out.append(f"<0x{byte:02X}>")
    return "".join(out)


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

    normalized_hex = bytes_to_hex_spaced(payload)
    return HexParseResult(True, "", payload, normalized_hex)


def read_raw_response_wait_idle(
    sock: socket.socket,
    initial_buffer: bytes,
    first_byte_timeout_s: float = FIRST_BYTE_TIMEOUT_S,
    idle_timeout_s: float = RAW_IDLE_TIMEOUT_S,
) -> RawReadResult:
    """
    Wait up to first_byte_timeout_s for the first byte to arrive (if none already),
    then keep reading until no new bytes arrive for idle_timeout_s.
    This matches how many device/test tools behave (e.g., 5000ms read timeout).
    """
    body = bytearray(initial_buffer)
    peer_closed = False

    if not body:
        ready, _, _ = select.select([sock], [], [], first_byte_timeout_s)
        if not ready:
            return RawReadResult(
                raw_response=b"",
                note=f"No response bytes received within first-byte timeout ({first_byte_timeout_s:.1f} s).",
                peer_closed=False,
            )

    sock.settimeout(idle_timeout_s)
    while True:
        try:
            chunk = sock.recv(4096)
            if chunk == b"":
                peer_closed = True
                break
            body.extend(chunk)
        except socket.timeout:
            break

    note = (
        f"Raw read: waited up to {first_byte_timeout_s:.1f}s for first byte, "
        f"then read until idle ({int(idle_timeout_s * 1000)} ms)."
    )
    return RawReadResult(raw_response=bytes(body), note=note, peer_closed=peer_closed)


class TcpWorker(QObject):
    connected = Signal(str, int)
    disconnected = Signal(str)
    send_result = Signal(bytes, bytes, str)
    error = Signal(str)

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
        if self._sock is not None:
            self.disconnected.emit("Already connected. Disconnect first.")
            return

        try:
            addr_infos = socket.getaddrinfo(host, port, socket.AF_UNSPEC, socket.SOCK_STREAM)
        except OSError as exc:
            self.error.emit(f"Connect failed: {exc}")
            return

        connect_error: Optional[Exception] = None
        sock: Optional[socket.socket] = None
        for family, socktype, proto, _canonname, sockaddr in addr_infos:
            candidate = socket.socket(family, socktype, proto)
            candidate.settimeout(CONNECT_TIMEOUT_S)
            try:
                candidate.connect(sockaddr)
                sock = candidate
                break
            except Exception as exc:
                connect_error = exc
                candidate.close()

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

    @Slot(bytes)
    def send_payload(self, payload: bytes) -> None:
        if self._sock is None:
            self.error.emit("Not connected.")
            return

        try:
            # WRITE
            self._sock.sendall(payload)

            # READ (raw device-friendly read; do not assume HTTP)
            raw_result = read_raw_response_wait_idle(
                self._sock,
                initial_buffer=self._recv_buffer,
                first_byte_timeout_s=FIRST_BYTE_TIMEOUT_S,
                idle_timeout_s=RAW_IDLE_TIMEOUT_S,
            )

            # We consumed any pending data for this request cycle
            self._recv_buffer = b""

            if raw_result.raw_response:
                self.send_result.emit(payload, raw_result.raw_response, raw_result.note)
            else:
                self.error.emit(raw_result.note)

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
            self.error.emit(f"Send/read failed: {exc}")
            self.disconnected.emit("Socket closed due to error.")


class MainWindow(QMainWindow):
    request_connect = Signal(str, int)
    request_disconnect = Signal()
    request_send = Signal(bytes)

    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("TCP Hex Sender")
        self.resize(1000, 760)

        self._is_connected = False
        self._connected_host = ""
        self._connected_port = 0
        self._last_hex_result = parse_hex_input("")
        self._history_blocks: list[str] = []

        self._build_ui()
        self._build_worker()
        self._wire_events()
        self._refresh_send_button_state()

    def _build_ui(self) -> None:
        root = QWidget()
        root_layout = QVBoxLayout(root)
        root_layout.setContentsMargins(10, 10, 10, 10)
        root_layout.setSpacing(8)

        top_row = QGridLayout()
        top_row.setHorizontalSpacing(8)

        self.host_input = QLineEdit("ci009ngppad-010")
        self.host_input.setPlaceholderText("Host")
        self.port_input = QSpinBox()
        self.port_input.setRange(1, 65535)
        self.port_input.setValue(12345)

        self.connect_btn = QPushButton("Connect")
        self.status_label = QLabel("Disconnected")
        self.status_label.setStyleSheet("color: #B00020; font-weight: 600;")

        top_row.addWidget(QLabel("Host"), 0, 0)
        top_row.addWidget(self.host_input, 0, 1)
        top_row.addWidget(QLabel("Port"), 0, 2)
        top_row.addWidget(self.port_input, 0, 3)
        top_row.addWidget(self.connect_btn, 0, 4)
        top_row.addWidget(QLabel("Status"), 0, 5)
        top_row.addWidget(self.status_label, 0, 6)

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
        self.history_edit.setMinimumHeight(260)
        self.history_edit.setWordWrapMode(QTextOption.NoWrap)

        mono = QFont("Menlo")
        mono.setStyleHint(QFont.Monospace)
        self.history_edit.setFont(mono)

        root_layout.addLayout(top_row)
        root_layout.addWidget(self.hex_label)
        root_layout.addWidget(self.hex_edit)
        root_layout.addWidget(self.hex_error_label)
        root_layout.addLayout(send_row)
        root_layout.addWidget(self.bytes_label)
        root_layout.addWidget(self.bytes_preview_edit)
        root_layout.addWidget(self.history_label)
        root_layout.addWidget(self.history_edit)

        self.setCentralWidget(root)

    def _build_worker(self) -> None:
        self.worker_thread = QThread(self)
        self.worker = TcpWorker()
        self.worker.moveToThread(self.worker_thread)
        self.worker_thread.start()

    def _wire_events(self) -> None:
        self.connect_btn.clicked.connect(self._on_connect_toggle)
        self.send_btn.clicked.connect(self._on_send_clicked)
        self.hex_edit.textChanged.connect(self._on_hex_text_changed)

        self.request_connect.connect(self.worker.connect_to_host)
        self.request_disconnect.connect(self.worker.disconnect_from_host)
        self.request_send.connect(self.worker.send_payload)

        self.worker.connected.connect(self._on_connected)
        self.worker.disconnected.connect(self._on_disconnected)
        self.worker.error.connect(self._on_worker_error)
        self.worker.send_result.connect(self._on_send_result)

    def closeEvent(self, event) -> None:  # type: ignore[override]
        if self.worker.is_connected:
            self.request_disconnect.emit()
        self.worker_thread.quit()
        self.worker_thread.wait(1500)
        super().closeEvent(event)

    def _set_connected_ui(self, connected: bool) -> None:
        self._is_connected = connected
        self.connect_btn.setText("Disconnect" if connected else "Connect")
        self.status_label.setText("Connected" if connected else "Disconnected")
        color = "#1E7D32" if connected else "#B00020"
        self.status_label.setStyleSheet(f"color: {color}; font-weight: 600;")
        self._refresh_send_button_state()

    def _refresh_send_button_state(self) -> None:
        self.send_btn.setEnabled(self._is_connected and self._last_hex_result.is_valid)

    def _append_history_block(self, block: str) -> None:
        self._history_blocks.insert(0, block)
        self.history_edit.setPlainText("\n\n".join(self._history_blocks))

    def _add_error_history(self, message: str) -> None:
        block = (
            f"[{timestamp_now()}] ERROR\n"
            f"Message: {message}"
        )
        self._append_history_block(block)

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

        self.send_btn.setEnabled(False)
        self.request_send.emit(self._last_hex_result.payload)

    @Slot()
    def _on_hex_text_changed(self) -> None:
        self._last_hex_result = parse_hex_input(self.hex_edit.toPlainText())

        if self._last_hex_result.is_valid:
            self.hex_error_label.setText("")
            self.bytes_preview_edit.setPlainText(bytes_preview(self._last_hex_result.payload))
        else:
            self.hex_error_label.setText(self._last_hex_result.error)
            self.bytes_preview_edit.setPlainText("Invalid hex input.")

        self._refresh_send_button_state()

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
        self._add_error_history(message)
        self._refresh_send_button_state()

    @Slot(bytes, bytes, str)
    def _on_send_result(self, sent: bytes, received: bytes, note: str) -> None:
        sent_hex = bytes_to_hex_spaced(sent)
        sent_preview = bytes_preview(sent)

        recv_hex = bytes_to_hex_spaced(received)
        recv_preview = bytes_preview(received)

        note_line = f"Note: {note}\n" if note else ""
        block = (
            f"[{timestamp_now()}]\n"
            f"Host: {self._connected_host}:{self._connected_port}\n"
            f"→ SENT\n"
            f"Sent Hex: {sent_hex}\n"
            f"Sent Bytes Preview: {sent_preview}\n"
            f"← RECV\n"
            f"Received Hex: {recv_hex}\n"
            f"Received Bytes Preview: {recv_preview}\n"
            f"{note_line}"
        ).rstrip()

        self._append_history_block(block)
        self._refresh_send_button_state()


def main() -> int:
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())
