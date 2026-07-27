"""
CyberGuard AI - Standalone Model Context Protocol (MCP) SQLite Server
Provides tools for local SQL queries against cyber threat intelligence,
user behavior baselines, security event logs, and response playbooks.
"""

import os
import sys
import sqlite3
import json
from typing import List, Dict, Any

from mcp.server.fastmcp import FastMCP

# Ensure database path resolution
DB_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data")
os.makedirs(DB_DIR, exist_ok=True)
DB_PATH = os.path.join(DB_DIR, "cyber_threats.db")

# Initialize FastMCP Server instance on port 5001
mcp = FastMCP("CyberGuard-MCP-Server", host="127.0.0.1", port=5001)

def get_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    """Initializes tables and populates sample cybersecurity datasets if DB is empty."""
    conn = get_connection()
    cursor = conn.cursor()

    # 1. Security Events Table
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

    # 2. Threat Intel Feed Table
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

    # 3. User Behavior Baselines Table
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

    # 4. Incident Response Playbooks Table
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

    # 5. Forensic Logs Table
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

    # Seed initial data if empty
    cursor.execute("SELECT COUNT(*) FROM threat_intel")
    if cursor.fetchone()[0] == 0:
        seed_data(cursor)
        conn.commit()

    conn.close()

def seed_data(cursor):
    """Populates database with realistic cybersecurity seed records."""
    threats = [
        ("CVE-2024-3094", "T1195.001", "XZ Utils Backdoor Supply Chain Attack", "CRITICAL",
         "Malicious injection into liblzma leading to sshd authentication bypass and RCE.",
         "process: sshd AND payload: /usr/sbin/sshd"),
        ("CVE-2023-34362", "T1190", "MOVEit Transfer SQL Injection Zero-Day", "CRITICAL",
         "Unauthenticated remote code execution via MOVEit Web application payload injection.",
         "HTTP POST /human.aspx AND SQL query contains DROP/EXEC"),
        ("CVE-2024-21683", "T1059.001", "Confluence Data Center Code Execution", "HIGH",
         "Authenticated remote code execution via macro plugin payload uploading.",
         "URI: /admin/app-properties.action"),
        ("CVE-2023-4966", "T1539", "Citrix Bleed Session Hijacking", "CRITICAL",
         "Buffer overflow in Citrix NetScaler Gateway causing session token leakage.",
         "HTTP GET /oauth/idp/.well-known/openid-configuration")
    ]
    cursor.executemany('''
        INSERT INTO threat_intel (cve_id, mitre_technique, threat_name, severity, description, indicator_pattern)
        VALUES (?, ?, ?, ?, ?, ?)
    ''', threats)

    playbooks = [
        ("Supply Chain Backdoor", "Containment: XZ Utils / SSHD Backdoor",
         json.dumps([
             "1. Isolate infected endpoint from corporate network VLAN immediately.",
             "2. Revoke active SSH sessions and invalidate API keys for impacted host.",
             "3. Roll back liblzma/xz packages to known clean version (5.4.x).",
             "4. Collect memory dump for forensic analysis.",
             "5. Require Tier-2 SOC Analyst approval before re-joining network."
         ]), 1, "CRITICAL"),
        ("SQL Injection Zero-Day", "Mitigation: Web Application Firewall Rule & App Patching",
         json.dumps([
             "1. Apply automated WAF IP block rule on offending source IP.",
             "2. Enable strict payload parameter validation on HTTP POST endpoints.",
             "3. Rotate database connection credentials.",
             "4. Trigger database forensic query audit."
         ]), 0, "HIGH"),
        ("Credential Stuffing", "Account Security Lockout & Token Revocation",
         json.dumps([
             "1. Enforce immediate password reset and MFA re-authentication for user.",
             "2. Invalidate current OAuth tokens.",
             "3. Rate limit target login endpoints."
         ]), 0, "MEDIUM")
    ]
    cursor.executemany('''
        INSERT INTO incident_playbooks (threat_category, title, response_steps, approval_required, risk_level)
        VALUES (?, ?, ?, ?, ?)
    ''', playbooks)

    baselines = [
        ("admin_sec", 15, "New York, USA", "MacBook Pro M2, Linux Terminal", 0),
        ("user_dev", 8, "London, UK", "Windows 11 Workstation", 1),
        ("sys_audit", 25, "Singapore", "Ubuntu Server Admin Jumpbox", 0)
    ]
    cursor.executemany('''
        INSERT INTO user_baselines (user_id, avg_daily_logins, typical_location, typical_devices, rare_process_count)
        VALUES (?, ?, ?, ?, ?)
    ''', baselines)


# ------------------ FastMCP Tool Registrations ------------------

@mcp.tool()
def query_sqlite_logs(query_str: str = "", limit: int = 10) -> List[Dict[str, Any]]:
    """MCP Tool: Queries security events log table from SQLite database."""
    conn = get_connection()
    cursor = conn.cursor()
    if query_str:
        cursor.execute("SELECT * FROM security_events WHERE payload LIKE ? OR event_type LIKE ? LIMIT ?",
                       (f"%{query_str}%", f"%{query_str}%", limit))
    else:
        cursor.execute("SELECT * FROM security_events ORDER BY id DESC LIMIT ?", (limit,))
    rows = [dict(r) for r in cursor.fetchall()]
    conn.close()
    return rows

@mcp.tool()
def search_threat_intel(pattern: str = "") -> List[Dict[str, Any]]:
    """MCP Tool: Searches threat intelligence signatures and MITRE techniques."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute('''
        SELECT * FROM threat_intel 
        WHERE cve_id LIKE ? OR mitre_technique LIKE ? OR threat_name LIKE ? OR description LIKE ?
    ''', (f"%{pattern}%", f"%{pattern}%", f"%{pattern}%", f"%{pattern}%"))
    rows = [dict(r) for r in cursor.fetchall()]
    conn.close()
    return rows

@mcp.tool()
def get_user_baseline(user_id: str) -> Dict[str, Any]:
    """MCP Tool: Retrieves user baseline activity metrics."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM user_baselines WHERE user_id = ?", (user_id,))
    row = cursor.fetchone()
    conn.close()
    return dict(row) if row else {}

@mcp.tool()
def fetch_playbook(threat_category: str) -> Dict[str, Any]:
    """MCP Tool: Retrieves automated response playbooks for a threat category."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM incident_playbooks WHERE threat_category LIKE ? OR title LIKE ?",
                   (f"%{threat_category}%", f"%{threat_category}%"))
    row = cursor.fetchone()
    conn.close()
    if row:
        res = dict(row)
        res["response_steps"] = json.loads(res["response_steps"])
        return res
    return {}

@mcp.tool()
def record_forensic_entry(incident_id: str, findings: str, status: str, action: str) -> bool:
    """MCP Tool: Logs a new incident forensic record into SQLite database."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO forensic_logs (incident_id, timestamp, agent_findings, status, action_taken)
        VALUES (?, datetime('now'), ?, ?, ?)
    ''', (incident_id, findings, status, action))
    conn.commit()
    conn.close()
    return True


if __name__ == "__main__":
    init_db()
    print("==================================================================")
    print("CyberGuard Standalone MCP SQLite Server starting...")
    print("• Transport: SSE (Server-Sent Events)")
    print("• Server Endpoint: http://127.0.0.1:5001/sse")
    print("• SQLite Database: ", DB_PATH)
    print("==================================================================")
    # Start FastMCP server listening on SSE transport
    mcp.run(transport="sse")

