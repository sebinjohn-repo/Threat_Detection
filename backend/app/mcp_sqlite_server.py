import os
import sqlite3
import json
import httpx
from typing import List, Dict, Any

class MCPSqliteServer:
    """
    Client Interface & Service Wrapper for the Standalone CyberGuard MCP Server.
    Connects to the standalone MCP server running on http://127.0.0.1:5001
    and provides local SQLite query fallbacks for multi-agent orchestrator workers.
    """

    def __init__(self, standalone_url: str = "http://127.0.0.1:5001", db_path: str = None):
        self.standalone_url = standalone_url.rstrip('/')
        if not db_path:
            db_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data")
            os.makedirs(db_dir, exist_ok=True)
            self.db_path = os.path.join(db_dir, "cyber_threats.db")
        else:
            self.db_path = db_path

        self._init_db()

    def is_standalone_online(self) -> bool:
        """Checks if the standalone MCP server process is active on port 5001."""
        try:
            with httpx.Client(timeout=1.0) as client:
                req = client.build_request("GET", f"{self.standalone_url}/sse")
                resp = client.send(req, stream=True)
                return resp.status_code == 200
        except Exception:
            return False


    def _get_connection(self):
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self):
        """Ensures local SQLite tables exist."""
        conn = self._get_connection()
        cursor = conn.cursor()

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS security_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                source_ip TEXT,
                dest_ip TEXT,
                event_type TEXT,
                severity TEXT,
                payload TEXT,
                anomaly_score REAL
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS threat_intel (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                cve_id TEXT,
                mitre_technique TEXT,
                threat_name TEXT,
                severity TEXT,
                description TEXT,
                indicator_pattern TEXT
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS user_baselines (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id TEXT UNIQUE,
                avg_daily_logins INTEGER,
                typical_location TEXT,
                typical_devices TEXT,
                rare_process_count INTEGER
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS incident_playbooks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                threat_category TEXT UNIQUE,
                title TEXT,
                response_steps TEXT,
                approval_required INTEGER,
                risk_level TEXT
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS forensic_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                incident_id TEXT,
                timestamp TEXT,
                agent_findings TEXT,
                status TEXT,
                action_taken TEXT
            )
        ''')

        conn.commit()
        conn.close()

    # ------------------ MCP Tools Invocation ------------------

    def query_sqlite_logs(self, query_str: str = "", limit: int = 10) -> List[Dict[str, Any]]:
        """Queries security events log table from SQLite database via standalone MCP tool logic."""
        conn = self._get_connection()
        cursor = conn.cursor()
        if query_str:
            cursor.execute("SELECT * FROM security_events WHERE payload LIKE ? OR event_type LIKE ? LIMIT ?",
                           (f"%{query_str}%", f"%{query_str}%", limit))
        else:
            cursor.execute("SELECT * FROM security_events ORDER BY id DESC LIMIT ?", (limit,))
        rows = [dict(r) for r in cursor.fetchall()]
        conn.close()
        return rows

    def search_threat_intel(self, pattern: str) -> List[Dict[str, Any]]:
        """Searches threat intelligence signatures and MITRE techniques via standalone MCP tool logic."""
        conn = self._get_connection()
        cursor = conn.cursor()
        cursor.execute('''
            SELECT * FROM threat_intel 
            WHERE cve_id LIKE ? OR mitre_technique LIKE ? OR threat_name LIKE ? OR description LIKE ?
        ''', (f"%{pattern}%", f"%{pattern}%", f"%{pattern}%", f"%{pattern}%"))
        rows = [dict(r) for r in cursor.fetchall()]
        conn.close()
        return rows

    def get_user_baseline(self, user_id: str) -> Dict[str, Any]:
        """Retrieves user baseline activity metrics via standalone MCP tool logic."""
        conn = self._get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM user_baselines WHERE user_id = ?", (user_id,))
        row = cursor.fetchone()
        conn.close()
        return dict(row) if row else {}

    def fetch_playbook(self, threat_category: str) -> Dict[str, Any]:
        """Retrieves automated response playbooks for a threat category via standalone MCP tool logic."""
        conn = self._get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM incident_playbooks WHERE threat_category LIKE ? OR title LIKE ?",
                       (f"%{threat_category}%", f"%{threat_category}%"))
        row = cursor.fetchone()
        conn.close()
        if row:
            res = dict(row)
            if isinstance(res.get("response_steps"), str):
                try:
                    res["response_steps"] = json.loads(res["response_steps"])
                except Exception:
                    pass
            return res
        return {}

    def record_forensic_entry(self, incident_id: str, findings: str, status: str, action: str) -> bool:
        """Logs a new incident forensic record into SQLite database via standalone MCP tool logic."""
        conn = self._get_connection()
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO forensic_logs (incident_id, timestamp, agent_findings, status, action_taken)
            VALUES (?, datetime('now'), ?, ?, ?)
        ''', (incident_id, findings, status, action))
        conn.commit()
        conn.close()
        return True

# Alias for backwards compatibility
MCPSqliteClient = MCPSqliteServer
