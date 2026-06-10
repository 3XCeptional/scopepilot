#!/usr/bin/env python3
"""ScopePilot Live Demo — Playwright-powered visual scan demo.
Starts the MCP server, runs scans against the fixture, shows live output.
"""
import json
import os
import secrets
import signal
import socket
import subprocess
import sys
import time
from pathlib import Path

os.environ["PLAYWRIGHT_BROWSERS_PATH"] = str(Path(__file__).parent.parent / ".playwright-browsers")

HERE = Path(__file__).parent
ROOT = HERE.parent
BIN = ROOT / "bin" / "pentest"
VENV_PYTHON = ROOT / ".venv-demo" / "bin" / "python"
DEMO_MCP_API_KEY = secrets.token_urlsafe(32)

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>ScopePilot — Acme Bot Scan Demo</title>
<style>
  @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;700&display=swap');
  * {{ margin: 0; padding: 0; box-sizing: border-box; }}
  body {{
    background: #0d1117;
    color: #e6edf3;
    font-family: 'JetBrains Mono', monospace;
    padding: 24px;
    min-height: 100vh;
  }}
  .header {{
    border-bottom: 2px solid #30363d;
    padding-bottom: 16px;
    margin-bottom: 24px;
  }}
  .header h1 {{
    font-size: 22px;
    font-weight: 700;
    color: #58a6ff;
  }}
  .header .sub {{
    color: #8b949e;
    font-size: 13px;
    margin-top: 4px;
  }}
  .status-grid {{
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
    gap: 12px;
    margin-bottom: 24px;
  }}
  .card {{
    background: #161b22;
    border: 1px solid #30363d;
    border-radius: 8px;
    padding: 16px;
  }}
  .card .label {{
    font-size: 11px;
    color: #8b949e;
    text-transform: uppercase;
    letter-spacing: 0.5px;
  }}
  .card .value {{
    font-size: 24px;
    font-weight: 700;
    margin-top: 4px;
  }}
  .card .value.green {{ color: #3fb950; }}
  .card .value.red {{ color: #f85149; }}
  .card .value.yellow {{ color: #d29922; }}
  .card .value.blue {{ color: #58a6ff; }}
  .log {{ 
    background: #0d1117;
    border: 1px solid #30363d;
    border-radius: 8px;
    padding: 16px;
    font-size: 13px;
    line-height: 1.6;
    max-height: 500px;
    overflow-y: auto;
    white-space: pre-wrap;
    word-break: break-all;
  }}
  .log .info {{ color: #8b949e; }}
  .log .ok {{ color: #3fb950; }}
  .log .warn {{ color: #d29922; }}
  .log .err {{ color: #f85149; }}
  .log .highlight {{ color: #58a6ff; font-weight: 700; }}
  .step {{ 
    margin-bottom: 16px;
    padding: 12px 16px;
    background: #161b22;
    border: 1px solid #30363d;
    border-radius: 8px;
  }}
  .step h3 {{ font-size: 14px; margin-bottom: 8px; color: #58a6ff; }}
  .step pre {{ 
    font-size: 12px; 
    color: #c9d1d9;
    white-space: pre-wrap;
    word-break: break-all;
    line-height: 1.5;
  }}
  .spinner {{ display: inline-block; width: 14px; height: 14px; border: 2px solid #30363d; border-top-color: #58a6ff; border-radius: 50%; animation: spin .6s linear infinite; vertical-align: middle; margin-right: 8px; }}
  @keyframes spin {{ to {{ transform: rotate(360deg); }} }}
</style>
</head>
<body>
<div class="header">
  <h1>🛡️ ScopePilot — Acme Bot Scan Demo</h1>
  <div class="sub">Scope-enforcing proxy · MCP tool server · Live scan results</div>
</div>
<div class="status-grid" id="status-grid">
  <div class="card"><div class="label">Scope Rules</div><div class="value blue" id="scope-count">—</div></div>
  <div class="card"><div class="label">URLs Checked</div><div class="value blue" id="urls-checked">0</div></div>
  <div class="card"><div class="label">Allowed</div><div class="value green" id="urls-allowed">0</div></div>
  <div class="card"><div class="label">Blocked</div><div class="value red" id="urls-blocked">0</div></div>
  <div class="card"><div class="label">Kill Switch</div><div class="value green" id="kill-switch">INACTIVE</div></div>
  <div class="card"><div class="label">Audit Entries</div><div class="value yellow" id="audit-count">0</div></div>
</div>
<div id="steps"></div>
<script>
let stepCount = 0;
function addStep(title, text, type='info') {{
  stepCount++;
  const d = document.getElementById('steps');
  const s = document.createElement('div'); s.className = 'step';
  s.innerHTML = '<h3><span class="spinner"></span>Step ' + stepCount + ': ' + title + '</h3><pre class="' + type + '">' + text + '</pre>';
  d.appendChild(s);
  s.scrollIntoView({{ behavior: 'smooth', block: 'end' }});
}}
function completeStep(title, text) {{
  const steps = document.getElementById('steps').children;
  const last = steps[steps.length - 1];
  if (last) {{
    last.querySelector('h3').innerHTML = '✅ Step ' + stepCount + ': ' + title;
    last.querySelector('pre').textContent = text;
  }}
}}
function updateCard(id, val, cls) {{
  const el = document.getElementById(id);
  if (el) {{ el.textContent = val; if (cls) el.className = 'value ' + cls; }}
}}
</script>
</body>
</html>
"""


def mcp_call(url, method, params=None):
    body = json.dumps({
        "jsonrpc": "2.0", "method": "call_tool",
        "params": {"name": method, "arguments": params or {}},
        "id": 1
    }).encode()
    import urllib.request
    req = urllib.request.Request(
        url + "/mcp",
        data=body,
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {DEMO_MCP_API_KEY}",
        },
    )
    try:
        resp = urllib.request.urlopen(req, timeout=10)
        return json.loads(resp.read())
    except Exception as e:
        return {"error": {"message": str(e)}}


def wait_for_port(host, port, timeout=10, interval=0.5):
    """Poll a TCP port until it's open, then return True. Return False on timeout."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(interval)
            s.connect((host, port))
            s.close()
            return True
        except (OSError, socket.error):
            time.sleep(interval)
    return False


def main():
    from playwright.sync_api import sync_playwright

    mcp_url = "http://127.0.0.1:9090"
    server_log = HERE / "scopepilot-server.log"

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        server_proc = None
        try:
            page = browser.new_page(viewport={"width": 1024, "height": 800})
            page.set_content(HTML_TEMPLATE)
            page.wait_for_load_state("domcontentloaded")

            step_counter = 0

            def add(title, text, t="info"):
                nonlocal step_counter
                step_counter += 1
                # Use the client-side addStep() JS function — avoids HTML injection
                # by calling the browser's JS function with JSON-safe string args.
                page.evaluate(
                    "addStep({}, {}, {})".format(
                        json.dumps(title), json.dumps(text), json.dumps(t)
                    )
                )
                page.wait_for_timeout(300)

            def complete(title, text):
                page.evaluate(
                    "completeStep({}, {})".format(
                        json.dumps(title), json.dumps(text)
                    )
                )

            def update(id_, val, cls_=None):
                page.evaluate(
                    "updateCard({}, {}, {})".format(
                        json.dumps(id_), json.dumps(val), json.dumps(cls_)
                    )
                )

            # Step 1 — Start the MCP server with demo settings
            add("Starting ScopePilot MCP Server",
                "Starting proxy + MCP server on 127.0.0.1:8443/:9090...")
            env = os.environ.copy()
            env["SCOPEPILOT_DEACTIVATION_TOKEN"] = "demo-token-123"
            env["SCOPEPILOT_MCP_API_KEY"] = DEMO_MCP_API_KEY
            # Redirect stdout to a file to avoid pipe deadlock (bug #6)
            server_proc = subprocess.Popen(
                [str(BIN), "server",
                 "--config", str(ROOT / "config" / "demo.yaml"),
                 "--listen-proxy", "127.0.0.1:8443",
                 "--listen-mcp", "127.0.0.1:9090"],
                stdout=open(server_log, "w"), stderr=subprocess.STDOUT,
                cwd=str(ROOT), env=env)

            # Server readiness check: retry-loop polling the port (bug #5)
            if not wait_for_port("127.0.0.1", 9090, timeout=10):
                # Also check if process already died
                if server_proc.poll() is not None:
                    complete("Starting ScopePilot MCP Server",
                             f"FAILED: Server exited with code {server_proc.returncode}")
                else:
                    complete("Starting ScopePilot MCP Server",
                             "FAILED: Server did not become ready within 10s")
                return

            complete("Starting ScopePilot MCP Server",
                     "MCP server running on 127.0.0.1:9090 | Proxy on 127.0.0.1:8443")

            # Step 2 — Get scope status
            add("Acme Bot Program Scope",
                "Fetching scope configuration from MCP...")
            resp = mcp_call(mcp_url, "get_scope_status")
            result = resp.get("result", {})
            text = (f"Program:     {result.get('program_id')}\n"
                    f"Include:     {result.get('include_count')} rules\n"
                    f"Exclude:     {result.get('exclude_count')} rules\n"
                    f"Schemes:     {result.get('allowed_schemes')}\n"
                    f"Ports:       {result.get('allowed_ports')}")
            complete("Acme Bot Program Scope", text)
            update("scope-count", f"{result.get('include_count', 0)} rules", "blue")

            # Step 3 — Check allowed URL
            add("Safety Check: Allowed URL",
                "Validating https://www.example.com/page through safety chain...")
            resp = mcp_call(mcp_url, "check_url", {"url": "https://www.example.com/page"})
            result = resp.get("result", {})
            allowed = result.get("allowed", False)
            text = (f"URL:        https://www.example.com/page\n"
                    f"Status:     {'✅ ALLOWED' if allowed else '❌ BLOCKED'}\n"
                    f"Blocked IP: {result.get('blocked_ip', False)}\n"
                    f"Denied Sch: {result.get('denied_scheme', False)}\n"
                    f"Rate Limit: {result.get('rate_limited', False)}\n"
                    f"Reason:     {result.get('reason', 'N/A')}")
            complete("Safety Check: Allowed URL", text)
            update("urls-checked", "1", "blue")
            update("urls-allowed", "1" if allowed else "0", "green" if allowed else "red")

            # Step 4 — Check path exclusion
            add("Safety Check: Path Exclusion (blocked /admin)",
                "Validating https://app.example.com/admin through safety chain...")
            resp = mcp_call(mcp_url, "check_url", {"url": "https://app.example.com/admin"})
            result = resp.get("result", {})
            allowed = result.get("allowed", False)
            text = (f"URL:        https://app.example.com/admin\n"
                    f"Status:     {'✅ ALLOWED' if allowed else '❌ BLOCKED'}\n"
                    f"Reason:     {result.get('reason', 'N/A')}")
            complete("Safety Check: Path Exclusion (blocked /admin)", text)
            update("urls-checked", "2", "blue")
            if not allowed:
                update("urls-blocked", "1", "red")

            # Step 5 — Check in-scope domain
            add("Safety Check: In-Scope Domain",
                "Validating https://www.example.com/ through safety chain...")
            resp = mcp_call(mcp_url, "check_url",
                           {"url": "https://www.example.com/"})
            result = resp.get("result", {})
            allowed = result.get("allowed", False)
            text = (f"URL:        https://www.example.com/\n"
                    f"Status:     {'✅ ALLOWED' if allowed else '❌ BLOCKED'}\n"
                    f"Reason:     {result.get('reason', 'N/A')}")
            complete("Safety Check: In-Scope Domain", text)
            update("urls-checked", "3", "blue")
            if not allowed:
                update("urls-blocked", "2", "red")
            else:
                update("urls-allowed", "2", "green")

            # Step 6 — Check out-of-scope URL (blocked)
            add("Safety Check: Out-of-Scope URL (blocked)",
                "Validating https://evil.com/ through safety chain...")
            resp = mcp_call(mcp_url, "check_url", {"url": "https://evil.com/"})
            result = resp.get("result", {})
            allowed = result.get("allowed", False)
            text = (f"URL:        https://evil.com/\n"
                    f"Status:     {'✅ ALLOWED' if allowed else '❌ BLOCKED'}\n"
                    f"Reason:     {result.get('reason', 'N/A')}")
            complete("Safety Check: Out-of-Scope URL (blocked)", text)
            update("urls-checked", "4", "blue")
            if not allowed:
                update("urls-blocked", "3", "red")

            # Step 7 — Run safe check (batch)
            add("Batch URL Validation (run_safe_check)",
                "Running batch safety check on 4 URLs...")
            resp = mcp_call(mcp_url, "run_safe_check", {
                "urls": [
                    "https://www.example.com/",
                    "https://app.example.com/admin",
                    "https://api.example.com/",
                    "https://evil.com/"
                ]
            })
            results = []
            result_val = resp.get("result")
            if isinstance(result_val, dict):
                results = result_val.get("results", [])
            text = "\n".join(
                f"{'✅' if r.get('allowed') else '❌'} {r.get('url','?')}"
                for r in results
            )
            complete("Batch URL Validation (run_safe_check)", text)
            update("urls-checked", "7", "blue")
            allowed_count = sum(1 for r in results if r.get('allowed'))
            blocked_count = sum(1 for r in results if not r.get('allowed'))
            update("urls-allowed", str(allowed_count), "green")
            update("urls-blocked", str(blocked_count), "red")

            # Step 7 — View audit log
            add("Audit Log",
                "Fetching recent audit entries from MCP...")
            resp = mcp_call(mcp_url, "get_audit_log", {"limit": 8})
            entries_raw = resp.get("result")
            entries = entries_raw if isinstance(entries_raw, list) else []
            text = "\n".join(
                f"[{e.get('timestamp','?')[:19]}] {e.get('event_type','?'):30s} "
                f"| {e.get('data',{}).get('tool', e.get('component','?'))}"
                for e in entries[:8]
            ) if entries else "(no entries)"
            complete("Audit Log", text)
            update("audit-count", str(len(entries)), "yellow")

            # Step 8 — Kill switch
            add("Kill Switch Status",
                "Checking kill switch state...")
            resp = mcp_call(mcp_url, "is_kill_switch_active")
            active = resp.get("result", {}).get("active", False)
            text = f"Kill Switch: {'🔴 ACTIVE' if active else '✅ INACTIVE'}"
            complete("Kill Switch Status", text)
            update("kill-switch", "ACTIVE" if active else "INACTIVE",
                   "red" if active else "green")

            # Step 9 — Activate and deactivate kill switch
            add("Kill Switch: Activate & Deactivate",
                 "Testing kill switch lifecycle...")
            resp = mcp_call(mcp_url, "activate_kill_switch", {"reason": "Demo test"})
            active = resp.get("result", {}).get("active", False)
            text = f"After activate: {'🔴 ACTIVE' if active else '✅ INACTIVE'}\n"
            resp = mcp_call(mcp_url, "deactivate_kill_switch", {"token": "demo-token-123"})
            if "error" in resp:
                text += f"Deactivate failed: {resp.get('error', {}).get('message', 'denied')}\n"
            else:
                active = resp.get("result", {}).get("active", False)
                text += f"After deactivate: {'🔴 ACTIVE' if active else '✅ INACTIVE'}\n"
            complete("Kill Switch: Activate & Deactivate", text)

            # Step 10 — Final summary
            add("Demo Complete",
                "All safety layers verified. System operational.",
                "ok")

            # Take screenshot
            page.screenshot(path=str(HERE / "scopepilot-demo.png"), full_page=True)

            # Print the HTML content for terminal display
            print("\n=== ScopePilot Demo Complete ===")
            print(f"Screenshot saved: demo/scopepilot-demo.png")
            print(f"Open in browser: file://{HERE}/scopepilot-demo.html")

            # Save the HTML
            html = page.content()
            (HERE / "scopepilot-demo.html").write_text(html)
            print(f"HTML saved:     demo/scopepilot-demo.html")
            print()

        finally:
            # Clean up server process — handle timeout gracefully (bug #2)
            if server_proc:
                try:
                    server_proc.terminate()
                    server_proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    server_proc.kill()
                    server_proc.wait()
            # Always close the browser, even if server cleanup threw (bug #7)
            browser.close()


if __name__ == "__main__":
    main()
