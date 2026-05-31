"""
SSH & Telnet Tools
Remote access, command execution, port forwarding, banner grabbing
"""
import socket
import logging
import time
from typing import Optional
from dataclasses import dataclass, field

logger = logging.getLogger("netmaster.protocols.remote")


# ─── SSH ───────────────────────────────────────────

@dataclass
class SSHResult:
    host: str
    port: int = 22
    username: str = ""
    connected: bool = False
    authenticated: bool = False
    output: str = ""
    error: str = ""
    session_id: str = ""
    tunnel_info: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "host": self.host, "port": self.port,
            "username": self.username, "connected": self.connected,
            "authenticated": self.authenticated,
            "output": self.output, "error": self.error,
            "session_id": self.session_id,
            "tunnel_info": self.tunnel_info,
        }


class SSHTool:
    """SSH 원격 접속 및 관리 도구"""

    def __init__(self, config: dict = None):
        self.config = config or {}
        self.default_port = self.config.get("ssh_port", 22)
        self.timeout = self.config.get("ssh_timeout", 10)
        self._sessions = {}

    def connect(self, host: str, username: str, password: str = None,
                key_file: str = None, port: int = None) -> dict:
        """SSH 접속"""
        import paramiko

        port = port or self.default_port
        result = SSHResult(host=host, port=port, username=username)

        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

            connect_kwargs = {
                "hostname": host,
                "port": port,
                "username": username,
                "timeout": self.timeout,
                "allow_agent": False,
                "look_for_keys": False,
            }

            if key_file:
                connect_kwargs["key_filename"] = key_file
            elif password:
                connect_kwargs["password"] = password
            else:
                # Try SSH agent
                connect_kwargs["allow_agent"] = True
                connect_kwargs["look_for_keys"] = True

            client.connect(**connect_kwargs)

            result.connected = True
            result.authenticated = True
            session_id = f"{username}@{host}:{port}"
            result.session_id = session_id
            self._sessions[session_id] = client

            # Get system info
            stdin, stdout, stderr = client.exec_command("uname -a")
            result.output = stdout.read().decode("utf-8", errors="replace").strip()

            logger.info(f"SSH connected: {session_id}")

        except paramiko.AuthenticationException:
            result.error = "Authentication failed"
        except paramiko.SSHException as e:
            result.error = f"SSH error: {e}"
        except socket.timeout:
            result.error = "Connection timed out"
        except Exception as e:
            result.error = str(e)

        return result.to_dict()

    def execute(self, session_id: str, command: str,
                timeout: int = 30) -> dict:
        """SSH 세션에서 명령 실행"""
        result = {"session_id": session_id, "command": command,
                  "output": "", "error": "", "exit_code": -1}

        client = self._sessions.get(session_id)
        if not client:
            result["error"] = "Session not found"
            return result

        try:
            stdin, stdout, stderr = client.exec_command(command, timeout=timeout)
            result["output"] = stdout.read().decode("utf-8", errors="replace")
            result["error"] = stderr.read().decode("utf-8", errors="replace")
            result["exit_code"] = stdout.channel.recv_exit_status()
        except Exception as e:
            result["error"] = str(e)

        return result

    def execute_batch(self, session_id: str, commands: list) -> dict:
        """SSH 세션에서 여러 명령 실행"""
        results = []
        for cmd in commands:
            r = self.execute(session_id, cmd)
            results.append(r)
            if r.get("exit_code", -1) != 0:
                break  # Error stop
        return {"session_id": session_id, "results": results}

    def sftp_upload(self, session_id: str, local_path: str,
                    remote_path: str) -> dict:
        """SFTP 파일 업로드"""
        result = {"session_id": session_id, "local": local_path,
                  "remote": remote_path, "error": ""}
        client = self._sessions.get(session_id)
        if not client:
            result["error"] = "Session not found"
            return result

        try:
            sftp = client.open_sftp()
            sftp.put(local_path, remote_path)
            sftp.close()
        except Exception as e:
            result["error"] = str(e)
        return result

    def sftp_download(self, session_id: str, remote_path: str,
                      local_path: str) -> dict:
        """SFTP 파일 다운로드"""
        result = {"session_id": session_id, "remote": remote_path,
                  "local": local_path, "error": ""}
        client = self._sessions.get(session_id)
        if not client:
            result["error"] = "Session not found"
            return result

        try:
            sftp = client.open_sftp()
            sftp.get(remote_path, local_path)
            sftp.close()
        except Exception as e:
            result["error"] = str(e)
        return result

    def start_tunnel(self, session_id: str, local_port: int,
                     remote_host: str, remote_port: int) -> dict:
        """SSH 포트 포워딩 (터널)"""
        result = {
            "session_id": session_id,
            "local_port": local_port,
            "remote_host": remote_host,
            "remote_port": remote_port,
            "tunnel_id": f"tun-{local_port}-{remote_host}-{remote_port}",
            "error": "",
        }

        client = self._sessions.get(session_id)
        if not client:
            result["error"] = "Session not found"
            return result

        try:
            transport = client.get_transport()
            transport.request_port_forward("", local_port)

            def handler(chan, host, port):
                sock = socket.socket()
                try:
                    sock.connect((host, port))
                except Exception:
                    return
                while True:
                    r, _, _ = select.select([sock, chan], [], [])
                    if sock in r:
                        data = sock.recv(1024)
                        if not data:
                            break
                        chan.send(data)
                    if chan in r:
                        data = chan.recv(1024)
                        if not data:
                            break
                        sock.send(data)
                chan.close()
                sock.close()

            result["status"] = "active"
        except Exception as e:
            result["error"] = str(e)

        return result

    def disconnect(self, session_id: str) -> bool:
        """SSH 세션 종료"""
        client = self._sessions.pop(session_id, None)
        if client:
            client.close()
            logger.info(f"SSH disconnected: {session_id}")
            return True
        return False

    def disconnect_all(self):
        """모든 SSH 세션 종료"""
        for sid in list(self._sessions.keys()):
            self.disconnect(sid)

    @property
    def active_sessions(self) -> list:
        return list(self._sessions.keys())


# ─── Telnet ────────────────────────────────────────

@dataclass
class TelnetResult:
    host: str
    port: int = 23
    connected: bool = False
    banner: str = ""
    output: str = ""
    error: str = ""

    def to_dict(self) -> dict:
        return {
            "host": self.host, "port": self.port,
            "connected": self.connected, "banner": self.banner,
            "output": self.output, "error": self.error,
        }


class TelnetTool:
    """Telnet 원격 접속 도구"""

    def __init__(self, config: dict = None):
        self.config = config or {}
        self.timeout = self.config.get("telnet_timeout", 10)

    def connect(self, host: str, port: int = 23, username: str = None,
                password: str = None) -> dict:
        """Telnet 접속"""
        import telnetlib

        result = TelnetResult(host=host, port=port)

        try:
            tn = telnetlib.Telnet(host, port, timeout=self.timeout)
            result.connected = True

            # Banner grab
            try:
                banner = tn.read_until(b"\n", timeout=3)
                result.banner = banner.decode("utf-8", errors="replace").strip()
            except Exception:
                pass

            # Login if credentials provided
            if username:
                tn.read_until(b"login: ", timeout=5)
                tn.write(username.encode("ascii") + b"\n")
                if password:
                    tn.read_until(b"Password: ", timeout=5)
                    tn.write(password.encode("ascii") + b"\n")

                time.sleep(1)
                output = tn.read_very_eager()
                result.output = output.decode("utf-8", errors="replace")

            tn.close()

        except ConnectionRefusedError:
            result.error = "Connection refused"
        except socket.timeout:
            result.error = "Connection timed out"
        except Exception as e:
            result.error = str(e)

        return result.to_dict()

    def grab_banner(self, host: str, port: int = 23) -> dict:
        """서비스 배너 수집"""
        result = TelnetResult(host=host, port=port)
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((host, port))
            banner = sock.recv(1024).decode("utf-8", errors="replace").strip()
            result.banner = banner
            result.connected = True
            sock.close()
        except Exception as e:
            result.error = str(e)
        return result.to_dict()

    def test_port(self, host: str, port: int) -> dict:
        """TCP 포트 연결 테스트"""
        result = {"host": host, "port": port, "open": False,
                  "response_ms": 0, "error": ""}
        try:
            start = time.time()
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((host, port))
            result["open"] = True
            result["response_ms"] = round((time.time() - start) * 1000, 2)
            sock.close()
        except (socket.timeout, ConnectionRefusedError, OSError) as e:
            result["error"] = str(e)
        return result
