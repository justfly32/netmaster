"""
NetMaster Web Dashboard
통합 네트워크 관리 웹 UI
"""
import json
import os
import logging
from pathlib import Path
from datetime import datetime

from flask import Flask, render_template, jsonify, request
from flask_socketio import SocketIO, emit
from protocols.web_terminal import WebTerminalManager

logger = logging.getLogger("netmaster.ui")

BASE_DIR = Path(__file__).parent.parent
TEMPLATE_DIR = BASE_DIR / "ui" / "templates"
STATIC_DIR = BASE_DIR / "ui" / "static"


def create_app(netmaster_app=None):
    """Flask 앱 생성"""
    app = Flask(__name__,
                template_folder=str(TEMPLATE_DIR),
                static_folder=str(STATIC_DIR))
    app.config["SECRET_KEY"] = os.environ.get("NETMASTER_SECRET", os.urandom(24).hex())
    socketio = SocketIO(app, cors_allowed_origins="*")
    app.terminal_manager = WebTerminalManager()

    # 메인 앱 참조
    app.netmaster = netmaster_app

    # ── Routes ──────────────────────────────────────

    @app.route("/")
    def index():
        return render_template("dashboard.html")

    @app.route("/api/status")
    def api_status():
        if app.netmaster:
            return jsonify(app.netmaster.get_status())
        return jsonify({"status": "ok", "mode": "standalone"})

    @app.route("/api/devices")
    def api_devices():
        if app.netmaster:
            return jsonify(app.netmaster.devices)
        return jsonify({})

    @app.route("/api/discover", methods=["POST"])
    def api_discover():
        subnet = request.json.get("subnet", None) if request.json else None
        if app.netmaster:
            devices = app.netmaster.discover_network(subnet)
            return jsonify(devices)
        return jsonify({"error": "NetMaster not initialized"}), 500

    @app.route("/api/topology")
    def api_topology():
        if app.netmaster and app.netmaster.topology:
            return jsonify(app.netmaster.topology)
        return jsonify({"nodes": [], "edges": []})

    @app.route("/api/ping", methods=["POST"])
    def api_ping():
        data = request.json or {}
        host = data.get("host", "")
        count = data.get("count", 4)
        if app.netmaster and host:
            result = app.netmaster.ping(host, count)
            return jsonify(result)
        return jsonify({"error": "Missing host"}), 400

    @app.route("/api/traceroute", methods=["POST"])
    def api_traceroute():
        data = request.json or {}
        host = data.get("host", "")
        max_hops = data.get("max_hops", 30)
        if app.netmaster and host:
            result = app.netmaster.traceroute(host, max_hops)
            return jsonify(result)
        return jsonify({"error": "Missing host"}), 400

    @app.route("/api/dns", methods=["POST"])
    def api_dns():
        data = request.json or {}
        domain = data.get("domain", "")
        record_type = data.get("type", "A")
        if app.netmaster and domain:
            result = app.netmaster.dns_lookup(domain, record_type)
            return jsonify(result)
        return jsonify({"error": "Missing domain"}), 400

    @app.route("/api/arp")
    def api_arp():
        subnet = request.args.get("subnet", None)
        if app.netmaster:
            result = app.netmaster.arp_scan(subnet)
            return jsonify(result)
        return jsonify({"error": "Not available"}), 500

    @app.route("/api/snmp", methods=["POST"])
    def api_snmp():
        data = request.json or {}
        host = data.get("host", "")
        oid = data.get("oid", "1.3.6.1.2.1.1.1.0")
        community = data.get("community", None)
        if app.netmaster and host:
            result = app.netmaster.snmp_query(host, oid, community)
            return jsonify(result)
        return jsonify({"error": "Missing host"}), 400

    @app.route("/api/ssh", methods=["POST"])
    def api_ssh():
        data = request.json or {}
        host = data.get("host", "")
        username = data.get("username", "")
        password = data.get("password", None)
        key_file = data.get("key_file", None)
        command = data.get("command", "")
        if app.netmaster and host and username:
            result = app.netmaster.ssh_connect(host, username, password, key_file)
            if command and result.get("authenticated"):
                session_id = result.get("session_id", "")
                exec_result = app.netmaster.execute(session_id, command)
                result["exec_result"] = exec_result
            return jsonify(result)
        return jsonify({"error": "Missing parameters"}), 400

    # ── WebSocket Events ────────────────────────────

    @socketio.on("connect")
    def ws_connect():
        emit("status", {"connected": True, "timestamp": datetime.now().isoformat()})

    @socketio.on("start_monitor")
    def ws_start_monitor(data):
        """실시간 모니터링 시작"""
        target = data.get("target", "")
        if app.netmaster and target:
            result = app.netmaster.ping(target, count=1)
            emit("ping_result", result)

    # ── Web Terminal Events ────────────────────────

    @socketio.on("terminal_connect")
    def ws_terminal_connect(data):
        """웹 터미널 세션 연결"""
        protocol = data.get("protocol", "ssh")
        host = data.get("host", "")
        port = int(data.get("port", 22 if protocol == "ssh" else 23))
        username = data.get("username", "")
        password = data.get("password", None)
        key_file = data.get("key_file", None)

        if not host or not username:
            emit("terminal_error", {"error": "Host and username are required"})
            return

        try:
            mgr = app.terminal_manager
            if protocol == "telnet":
                session_id = mgr.create_telnet_session(host, port, username, password)
            else:
                session_id = mgr.create_ssh_session(host, port, username, password, key_file)

            def on_output(sid, data):
                emit("terminal_output", {
                    "session_id": sid,
                    "data": data.decode("utf-8", errors="replace"),
                })

            def on_disconnect(sid):
                emit("terminal_disconnected", {"session_id": sid})

            mgr.set_output_callback(session_id, on_output)
            mgr.set_disconnect_callback(session_id, on_disconnect)

            emit("terminal_connected", {"session_id": session_id})
            logger.info(f"Terminal connected: {protocol} {username}@{host}:{port}")

        except Exception as e:
            logger.error(f"Terminal connect error: {e}")
            emit("terminal_error", {"error": str(e)})

    @socketio.on("terminal_input")
    def ws_terminal_input(data):
        """웹 터미널 입력 전달"""
        session_id = data.get("session_id", "")
        input_data = data.get("data", "")
        if app.terminal_manager.is_valid(session_id) and input_data:
            app.terminal_manager.write(session_id, input_data.encode("utf-8"))

    @socketio.on("terminal_resize")
    def ws_terminal_resize(data):
        """웹 터미널 크기 변경"""
        session_id = data.get("session_id", "")
        cols = int(data.get("cols", 80))
        rows = int(data.get("rows", 24))
        if app.terminal_manager.is_valid(session_id):
            app.terminal_manager.resize(session_id, cols, rows)

    @socketio.on("terminal_disconnect")
    def ws_terminal_disconnect(data):
        """웹 터미널 세션 종료"""
        session_id = data.get("session_id", "")
        app.terminal_manager.disconnect(session_id)
        emit("terminal_disconnected", {"session_id": session_id})
        logger.info(f"Terminal disconnected: {session_id}")

    return app


# 직접 실행 시
if __name__ == "__main__":
    from main import NetMaster
    app = NetMaster()
    flask_app = create_app(app)
    flask_app.run(host="0.0.0.0", port=8080, debug=True, threaded=True)
