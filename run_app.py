"""
CyberGuard AI - Unified Application Launcher
Launches the Standalone MCP Server process, Flask backend server,
and automatically opens the Glassmorphic UI in your browser.
"""

import os
import sys
import time
import webbrowser
import subprocess
import threading

def start_mcp_server():
    """Starts the standalone FastMCP SQLite Server process on port 5001."""
    python_exe = sys.executable
    mcp_script = os.path.join(os.path.dirname(__file__), "backend", "app", "mcp_server.py")
    subprocess.Popen([python_exe, mcp_script])

def main():
    # Ensure working directory is project root
    project_root = os.path.dirname(os.path.abspath(__file__))
    os.chdir(project_root)
    sys.path.insert(0, os.path.join(project_root, "backend"))

    print("==================================================================")
    print("[CyberGuard AI] Starting CyberGuard AI Platform...")
    print("==================================================================")
    print("• Standalone MCP Server: http://127.0.0.1:5001/sse")
    print("• Backend API Server:     http://localhost:5000/api")
    print("• Frontend UI Dashboard:  http://localhost:5000")
    print("==================================================================")

    # Prevent duplicate browser opening and subprocess spawns during Flask debug hot-reloads
    if os.environ.get("WERKZEUG_RUN_MAIN") != "true":
        # 1. Start Standalone MCP Server Process once
        threading.Thread(target=start_mcp_server, daemon=True).start()
        time.sleep(1.0)

        # 2. Automatically open web browser once
        def open_browser():
            time.sleep(1.5)
            webbrowser.open("http://localhost:5000")

        threading.Thread(target=open_browser, daemon=True).start()

    # 3. Import and run Flask app
    from backend.app.main import app
    app.run(host="0.0.0.0", port=5000, debug=True)


if __name__ == "__main__":
    main()
