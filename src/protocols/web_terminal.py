"""
Web-based Interactive Terminal Manager
SSH/Telnet interactive sessions bridged to WebSocket
"""
import time
import socket
import logging
import threading

logger = logging.getLogger("netmaster.protocols.terminal")


# ─── Telnet Protocol ──────────────────────────────

IAC = bytes([255])
DONT = bytes([254])
DO = bytes([253])
WONT = bytes([252])
WILL = bytes([251])
SB = bytes([250])
SE = bytes([240])


def _negotiate_telnet(data: bytes) -> bytes:
    result = bytearray()
    i = 0
    while i < len(data):
        if data[i] == 255 and i + 2 < len(data):
            cmd = data[i + 1]
            if cmd in (WILL, WONT, DO, DONT):
                i += 3
                continue
            elif cmd == SB:
                i += 3
                while i < len(data):
                    if data[i] == 255 and i + 1 < len(data) and data[i + 1] == SE:
                        i += 2
                        break
                    i += 1
                continue
        result.append(data[i])
        i += 1
    return bytes(result)


# ─── SSH Session ──────────────────────────────────

class SSHSession:
    def __init__(self, session_id, host, port, username, password=None, key_file=None):
        self.session_id = session_id
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.key_file = key_file
        self.client = None
        self.channel = None
        self.running = False
        self.thread = None
        self.on_output = None
        self.on_disconnect = None

    def connect(self):
        import paramiko
        self.client = paramiko.SSHClient()
        self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        kwargs = {
            "hostname": self.host,
            "port": self.port,
            "username": self.username,
            "timeout": 10,
            "allow_agent": False,
            "look_for_keys": False,
        }
        if self.key_file:
            kwargs["key_filename"] = self.key_file
        elif self.password:
            kwargs["password"] = self.password
        else:
            kwargs["allow_agent"] = True
            kwargs["look_for_keys"] = True
        self.client.connect(**kwargs)
        self.channel = self.client.invoke_shell(term="xterm-256color")
        self.channel.settimeout(0.0)
        self.running = True
        self.thread = threading.Thread(target=self._read_loop, daemon=True)
        self.thread.start()

    def _read_loop(self):
        while self.running:
            try:
                if self.channel.recv_ready():
                    data = self.channel.recv(65535)
                    if data:
                        if self.on_output:
                            self.on_output(self.session_id, data)
                    else:
                        break
                else:
                    time.sleep(0.005)
            except Exception:
                break
        self._cleanup()

    def write(self, data: bytes):
        if self.channel and self.running:
            try:
                self.channel.send(data)
            except Exception:
                self._cleanup()

    def resize(self, cols: int, rows: int):
        if self.channel and self.running:
            try:
                self.channel.resize_pty(width=cols, height=rows)
            except Exception:
                pass

    def _cleanup(self):
        self.running = False
        try:
            if self.channel:
                self.channel.close()
        except Exception:
            pass
        try:
            if self.client:
                self.client.close()
        except Exception:
            pass
        if self.on_disconnect:
            self.on_disconnect(self.session_id)

    def close(self):
        self.running = False
        self._cleanup()


# ─── Telnet Session ───────────────────────────────

class TelnetSession:
    def __init__(self, session_id, host, port, username=None, password=None):
        self.session_id = session_id
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.sock = None
        self.running = False
        self.thread = None
        self.on_output = None
        self.on_disconnect = None
        self._buffer = b""

    def connect(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.settimeout(10.0)
        self.sock.connect((self.host, self.port))
        self.sock.setblocking(False)
        self.running = True
        self.thread = threading.Thread(target=self._read_loop, daemon=True)
        self.thread.start()
        if self.username:
            time.sleep(0.5)
            self.write(f"{self.username}\n".encode())
            if self.password:
                time.sleep(0.3)
                self.write(f"{self.password}\n".encode())

    def _read_loop(self):
        while self.running:
            try:
                data = self.sock.recv(65535)
                if data:
                    text = _negotiate_telnet(data)
                    if text and self.on_output:
                        self.on_output(self.session_id, text)
                    self._buffer += data
                    if self.username and self.password:
                        lb = self._buffer.lower()
                        if b"login:" in lb:
                            self.write(f"{self.username}\n".encode())
                            self._buffer = b""
                        elif b"password:" in lb:
                            self.write(f"{self.password}\n".encode())
                            self._buffer = b""
                else:
                    break
            except (socket.error, BlockingIOError):
                time.sleep(0.005)
            except Exception:
                break
        self._cleanup()

    def write(self, data: bytes):
        if self.sock and self.running:
            try:
                self.sock.send(data)
            except Exception:
                self._cleanup()

    def resize(self, cols: int, rows: int):
        if self.sock and self.running:
            try:
                NAWS = bytes([
                    255, 250, 31,
                    0, cols & 0xFF, (cols >> 8) & 0xFF,
                    0, rows & 0xFF, (rows >> 8) & 0xFF,
                    255, 240,
                ])
                self.sock.send(NAWS)
            except Exception:
                pass

    def _cleanup(self):
        self.running = False
        try:
            if self.sock:
                self.sock.close()
        except Exception:
            pass
        if self.on_disconnect:
            self.on_disconnect(self.session_id)

    def close(self):
        self.running = False
        self._cleanup()


# ─── Session Manager ──────────────────────────────

class WebTerminalManager:
    def __init__(self):
        self._sessions = {}
        self._lock = threading.Lock()

    def create_ssh_session(self, host, port, username, password=None, key_file=None):
        port = port or 22
        session_id = f"ssh-{username}@{host}:{port}-{int(time.time() * 1000000)}"
        session = SSHSession(session_id, host, port, username, password, key_file)
        with self._lock:
            self._sessions[session_id] = session
        try:
            session.connect()
            return session_id
        except Exception:
            with self._lock:
                self._sessions.pop(session_id, None)
            raise

    def create_telnet_session(self, host, port, username=None, password=None):
        port = port or 23
        session_id = f"telnet-{username or 'anon'}@{host}:{port}-{int(time.time() * 1000000)}"
        session = TelnetSession(session_id, host, port, username, password)
        with self._lock:
            self._sessions[session_id] = session
        try:
            session.connect()
            return session_id
        except Exception:
            with self._lock:
                self._sessions.pop(session_id, None)
            raise

    def write(self, session_id, data):
        session = self._sessions.get(session_id)
        if session:
            session.write(data)

    def resize(self, session_id, cols, rows):
        session = self._sessions.get(session_id)
        if session:
            session.resize(cols, rows)

    def disconnect(self, session_id):
        with self._lock:
            session = self._sessions.pop(session_id, None)
        if session:
            session.close()
            return True
        return False

    def set_output_callback(self, session_id, callback):
        session = self._sessions.get(session_id)
        if session:
            session.on_output = callback

    def set_disconnect_callback(self, session_id, callback):
        session = self._sessions.get(session_id)
        if session:
            session.on_disconnect = callback

    def get_active_sessions(self):
        return list(self._sessions.keys())

    def disconnect_all(self):
        with self._lock:
            ids = list(self._sessions.keys())
            for sid in ids:
                session = self._sessions.pop(sid, None)
                if session:
                    session.close()

    def is_valid(self, session_id):
        return session_id in self._sessions
