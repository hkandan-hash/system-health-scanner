"""sysscan: check that this Windows machine and its apps are up, then write an HTML report.

Usage:
  python sysscan.py scan                     run checks, write report, exit 1 if anything is not UP
  python sysscan.py report                   rebuild the report from the last saved scan
  python sysscan.py dashboard [--interval 60] [--port 8765]
"""
import argparse
import contextlib
import ctypes
import datetime as dt
import html
import io
import json
import secrets
import shutil
import socket
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import yaml

# In the packaged .exe, config and results live next to the .exe.
HERE = Path(sys.executable).parent if getattr(sys, "frozen", False) else Path(__file__).resolve().parent
NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)  # no console pop-ups from the desktop app
RESULTS = HERE / "results"
REPORT = RESULTS / "report.html"
KEEP_SCANS = 6000  # about 24 h of history at the dashboard's 15 s interval
SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}

# Read-only: one PowerShell call that only uses Get-* cmdlets.
PS_SNAPSHOT = (
    "$c=(Get-CimInstance Win32_Processor | Measure-Object LoadPercentage -Average).Average;"
    "$s=@{}; Get-Service -ErrorAction SilentlyContinue | ForEach-Object { $s[$_.Name]=[string]$_.Status };"
    "$p=@(Get-Process | ForEach-Object { $_.ProcessName } | Sort-Object -Unique);"
    "@{cpu=$c; services=$s; processes=$p} | ConvertTo-Json -Compress -Depth 3"
)


class _MemStatus(ctypes.Structure):
    _fields_ = [("dwLength", ctypes.c_ulong), ("dwMemoryLoad", ctypes.c_ulong)] + [
        (n, ctypes.c_ulonglong)
        for n in ("total", "avail", "pf_total", "pf_avail", "v_total", "v_avail", "v_ext")
    ]


def ps_snapshot():
    out = subprocess.run(
        ["powershell", "-NoProfile", "-NonInteractive", "-Command", PS_SNAPSHOT],
        capture_output=True, text=True, encoding="utf-8", timeout=90, creationflags=NO_WINDOW,
    )
    if out.returncode != 0:
        raise RuntimeError(out.stderr.strip()[:300] or "PowerShell failed")
    data = json.loads(out.stdout)
    return {
        "cpu": data.get("cpu"),
        "services": {k.lower(): v for k, v in (data.get("services") or {}).items()},
        "processes": {p.lower() for p in data.get("processes") or []},
    }


def check(kind, target, name, ok, detail, fix, severity):
    status = "UP" if ok is True else "DOWN" if ok is False else "UNKNOWN"
    return {"key": f"{kind}:{target}", "kind": kind, "name": name, "status": status,
            "detail": detail, "fix": fix if status != "UP" else "", "severity": severity}


def check_app(item, snap, snap_err):
    kind = next((k for k in ("service", "process", "port", "http") if k in item), None)
    if kind is None:
        raise ValueError(f"apps.yml entry needs service, process, port or http: {item}")
    target = str(item[kind])
    name = item.get("name", target)
    sev = item.get("severity", "high")

    if kind in ("service", "process") and snap is None:
        return check(kind, target, name, None, f"could not read {kind}es: {snap_err}",
                     "Run sysscan from a normal PowerShell window and check that PowerShell works.", sev)
    if kind == "service":
        st = snap["services"].get(target.lower())
        return check(kind, target, name, st == "Running", f"service status: {st or 'not installed'}",
                     f"Start-Service {target}   (if it stops again, look in Event Viewer > Windows Logs > System)", sev)
    if kind == "process":
        proc = target.lower().removesuffix(".exe")
        ok = proc in snap["processes"]
        return check(kind, target, name, ok, "running" if ok else "not running",
                     f"Start the application that runs {proc}.exe, and check its log for crash errors.", sev)
    if kind == "port":
        host = item.get("host", "127.0.0.1")
        target = f"{host}:{target}"
        try:
            with socket.create_connection((host, int(item["port"])), timeout=3):
                ok, detail = True, "accepting connections"
        except OSError as e:
            ok, detail = False, f"no connection ({e.__class__.__name__})"
        return check(kind, target, name, ok, detail,
                     f"Nothing is listening on {target}. Start the app that owns this port, and check the firewall.", sev)
    # http
    expect = int(item.get("expect", 200))
    start = time.perf_counter()
    try:
        with urllib.request.urlopen(urllib.request.Request(target, method="GET"), timeout=5) as r:
            code = r.status
    except urllib.error.HTTPError as e:
        code = e.code
    except (urllib.error.URLError, OSError) as e:
        return check(kind, target, name, False, f"no response ({getattr(e, 'reason', e)})",
                     f"The web app at {target} isn't answering. Start it, or check its host and port.", sev)
    ms = int((time.perf_counter() - start) * 1000)
    return check(kind, target, name, code == expect, f"HTTP {code} in {ms} ms (expected {expect})",
                 f"{target} returned HTTP {code}. Check the app's error log.", sev)


def health_checks(cfg, cpu):
    h = cfg.get("health") or {}
    out = []
    if cpu is not None:
        lim = h.get("cpu_max", 90)
        out.append(check("health", "cpu", "CPU load", cpu < lim, f"{cpu}% (limit {lim}%)",
                         "Find the busy process in Task Manager > Details, sorted by CPU.", "medium"))
    mem = _MemStatus()
    mem.dwLength = ctypes.sizeof(_MemStatus)
    if ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(mem)):
        lim = h.get("memory_max", 90)
        out.append(check("health", "memory", "Memory use", mem.dwMemoryLoad < lim,
                         f"{mem.dwMemoryLoad}% of {mem.total / 2**30:.1f} GB (limit {lim}%)",
                         "Close or restart the process using the most memory (Task Manager > Details).", "medium"))
    for disk in h.get("disks", ["C:\\"]):
        lim = h.get("disk_max", 90)
        try:
            u = shutil.disk_usage(disk)
        except OSError as e:
            out.append(check("health", f"disk {disk}", f"Disk {disk}", False, str(e), f"Check that drive {disk} exists.", "high"))
            continue
        pct = round(u.used * 100 / u.total, 1)
        out.append(check("health", f"disk {disk}", f"Disk {disk}", pct < lim,
                         f"{pct}% used, {u.free / 2**30:.1f} GB free (limit {lim}%)",
                         f"Free space on {disk}: empty temp folders, run Disk Cleanup, move large files.", "high"))
    return out


def scan(cfg):
    try:
        snap, snap_err = ps_snapshot(), None
    except Exception as e:  # noqa: BLE001 - report it, don't crash the scan
        snap, snap_err = None, str(e)
    checks = health_checks(cfg, snap and snap["cpu"])
    checks += [check_app(item, snap, snap_err) for item in cfg.get("apps") or []]
    result = {
        "host": socket.gethostname(),
        "time": dt.datetime.now().isoformat(timespec="seconds"),
        "uptime_hours": round(ctypes.windll.kernel32.GetTickCount64() / 3_600_000, 1),
        "checks": checks,
    }
    RESULTS.mkdir(exist_ok=True)
    stamp = dt.datetime.now().strftime("%Y%m%d-%H%M%S")
    (RESULTS / f"scan-{stamp}.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
    for old in sorted(RESULTS.glob("scan-*.json"))[:-KEEP_SCANS]:
        old.unlink()
    return result


def saved_scans():
    files = sorted(RESULTS.glob("scan-*.json"))[-2:]
    scans = [json.loads(f.read_text(encoding="utf-8")) for f in files]
    return (scans[-1] if scans else None), (scans[0] if len(scans) == 2 else None)


def changes(cur, prev):
    if prev is None:
        return ["First scan, so there is nothing to compare yet."]
    before = {c["key"]: c for c in prev["checks"]}
    now_keys = {c["key"] for c in cur["checks"]}
    out = []
    for c in cur["checks"]:
        b = before.get(c["key"])
        if b is None:
            out.append(f"New check: {c['name']} is {c['status']}")
        elif b["status"] != c["status"]:
            word = "RECOVERED" if c["status"] == "UP" else "WENT DOWN" if b["status"] == "UP" else "CHANGED"
            out.append(f"{word}: {c['name']} ({b['status']} → {c['status']})")
    out += [f"Check removed: {before[k]['name']}" for k in before.keys() - now_keys]
    return out or [f"No changes since {prev['time']}."]


class History:
    """The last 24 h of results, kept in memory so analytics stay fast at a 15 s scan interval."""

    def __init__(self, hours=24):
        self.hours = hours
        self.items = []  # (timestamp, {check key: is_up})

    def load(self):
        start = time.time() - self.hours * 3600
        for f in sorted(RESULTS.glob("scan-*.json")):
            try:
                if f.stat().st_mtime >= start:
                    self.add(f.stat().st_mtime, json.loads(f.read_text(encoding="utf-8")))
            except (OSError, ValueError, KeyError):
                continue
        return self

    def add(self, ts, scan):
        self.items.append((ts, {c["key"]: c["status"] == "UP" for c in scan["checks"]}))
        start = time.time() - self.hours * 3600
        while self.items and self.items[0][0] < start:
            self.items.pop(0)

    def analytics(self, keys=None, slots=48):
        """Per check: uptime %, incidents (UP -> DOWN transitions), and a strip of slots
        (True = all UP, False = DOWN at least once, None = no scan). Plus overall availability.
        `keys` limits it to the current checks, so removed checks don't skew the totals."""
        start = time.time() - self.hours * 3600
        span = self.hours * 3600 / slots
        per, last = {}, {}
        all_up = incidents = n = 0
        for ts, row in self.items:
            if keys is not None:
                row = {k: v for k, v in row.items() if k in keys}
                if not row:
                    continue
            n += 1
            i = min(max(int((ts - start) / span), 0), slots - 1)
            all_up += all(row.values())
            for k, up in row.items():
                p = per.setdefault(k, {"strip": [None] * slots, "up": 0, "n": 0, "incidents": 0})
                p["n"] += 1
                p["up"] += up
                if p["strip"][i] is not False:
                    p["strip"][i] = up
                if last.get(k) is True and not up:
                    p["incidents"] += 1
                    incidents += 1
                last[k] = up
        for p in per.values():
            p["uptime"] = round(100 * p["up"] / p["n"], 1)
        return {"checks": per, "scans": n, "incidents": incidents,
                "availability": round(100 * all_up / n, 1) if n else None}


def render(cur, prev, strips=None):
    """Static HTML report (results/report.html)."""
    e = html.escape
    bad = sorted((c for c in cur["checks"] if c["status"] != "UP"),
                 key=lambda c: (SEV_ORDER.get(c["severity"], 9), c["kind"] != "health"))
    up = len(cur["checks"]) - len(bad)
    overall = "ALL UP" if not bad else f"{len(bad)} PROBLEM{'S' if len(bad) > 1 else ''}"
    color = "#1a7f37" if not bad else "#cf222e"
    fixes = "".join(f"<li><b>{e(c['name'])}</b> <span class=sev>{e(c['severity'])}</span>: "
                    f"{e(c['detail'])}<br><code>{e(c['fix'])}</code></li>" for c in bad) or "<li>Nothing to fix.</li>"
    if strips is None:
        strips = {k: v["strip"] for k, v in History().load().analytics()["checks"].items()}

    def strip(key):
        return "".join(f"<i class=h{ {True: 'UP', False: 'DOWN'}.get(s, '') }></i>" for s in strips.get(key, []))

    rows = "".join(f"<tr><td class={c['status']}>{c['status']}</td><td>{e(c['name'])}</td>"
                   f"<td>{e(c['kind'])}</td><td>{e(c['detail'])}</td><td class=hist>{strip(c['key'])}</td></tr>"
                   for c in cur["checks"])
    diff = "".join(f"<li>{e(x)}</li>" for x in changes(cur, prev))
    return f"""<!DOCTYPE html><html><head><meta charset="utf-8"><title>sysscan: {e(cur['host'])}</title>
<style>body{{font:15px system-ui,sans-serif;max-width:960px;margin:2em auto;padding:0 1em;color:#1f2328}}
h1 span{{color:{color}}} table{{border-collapse:collapse;width:100%}} td,th{{border-bottom:1px solid #d0d7de;padding:6px;text-align:left}}
.UP{{color:#1a7f37;font-weight:600}} .DOWN,.UNKNOWN{{color:#cf222e;font-weight:600}} code{{background:#f6f8fa;padding:2px 4px}}
.sev{{font-size:12px;background:#eee;padding:1px 6px;border-radius:8px}} li{{margin-bottom:8px}}
.hist{{white-space:nowrap}} .hist i{{display:inline-block;width:4px;height:14px;margin-right:1px;background:#eaeef2}}
.hist i.hUP{{background:#2da44e}} .hist i.hDOWN{{background:#cf222e}}
</style></head><body>
<h1>{e(cur['host'])}: <span>{overall}</span></h1>
<p>Scanned {e(cur['time'])} · {up}/{len(cur['checks'])} checks up · machine up {cur['uptime_hours']} h</p>
<h2>Fix first</h2><ol>{fixes}</ol>
<h2>Changes since last scan</h2><ul>{diff}</ul>
<h2>All checks</h2><table><tr><th>Status</th><th>Check</th><th>Type</th><th>Detail</th><th>Last 24 h</th></tr>{rows}</table>
</body></html>"""


def load_cfg(path):
    return yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}


def run_scan(config):
    """Scan, write the report, print one line per check. Returns 0 if everything is UP, else 1."""
    cur = scan(load_cfg(config))
    _, prev = saved_scans()
    REPORT.write_text(render(cur, prev), encoding="utf-8")
    for c in cur["checks"]:
        print(f"{c['status']:8} {c['name']:30} {c['detail']}")
    print(f"Report: {REPORT}")
    return 0 if all(c["status"] == "UP" for c in cur["checks"]) else 1


def main(argv=None):
    ap = argparse.ArgumentParser(description="Check that this machine and its apps are up.")
    ap.add_argument("command", choices=["scan", "report", "dashboard"])
    ap.add_argument("--config", default=str(HERE / "apps.yml"))
    ap.add_argument("--interval", type=int, default=15, help="dashboard: seconds between scans")
    ap.add_argument("--port", type=int, default=8765, help="dashboard: local port")
    a = ap.parse_args(argv)

    if a.command == "report":
        cur, prev = saved_scans()
        if cur is None:
            sys.exit("No saved scans yet. Run: python sysscan.py scan")
        REPORT.write_text(render(cur, prev), encoding="utf-8")
        print(f"Report: {REPORT}")
        return

    if a.command == "scan":
        sys.exit(run_scan(a.config))

    # dashboard: scan in the background, serve a live page + JSON API on localhost only
    import sysfix  # in-process, so it also works inside the packaged .exe

    hist = History().load()
    state = {"scan": saved_scans()[0], "fix": None, "busy": None}
    token = secrets.token_urlsafe(16)  # required on POST, so other websites can't trigger scans/fixes
    hosts = {f"127.0.0.1:{a.port}", f"localhost:{a.port}"}  # blocks DNS-rebinding reads
    scan_lock, fix_lock = threading.Lock(), threading.Lock()

    def do_scan():
        with scan_lock:
            cur = scan(load_cfg(a.config))
            _, prev = saved_scans()
            hist.add(time.time(), cur)
            state["scan"] = cur
            strips = {k: v["strip"] for k, v in hist.analytics()["checks"].items()}
            REPORT.write_text(render(cur, prev, strips), encoding="utf-8")

    def do_fix():
        if not fix_lock.acquire(blocking=False):
            return "A fix is already running."
        state["busy"] = "fix"
        buf = io.StringIO()
        try:
            with contextlib.redirect_stdout(buf):
                try:
                    code = sysfix.main(["--apply", "--config", a.config])
                except SystemExit as ex:
                    code = ex.code
            state["fix"] = f"{dt.datetime.now():%H:%M:%S}  exit {code}\n{buf.getvalue()}".strip()
            do_scan()
        finally:
            state["busy"] = None
            fix_lock.release()
        return state["fix"]

    def status():
        cur = state["scan"]
        an = hist.analytics({c["key"] for c in cur["checks"]} if cur else None)
        try:
            fixable = len(sysfix.plan(cur, sysfix.fixes_from_config(a.config))[0]) if cur else 0
        except Exception:  # noqa: BLE001 - a bad apps.yml shouldn't break the page
            fixable = 0
        rows = []
        for c in (cur or {}).get("checks", []):
            s = an["checks"].get(c["key"], {})
            rows.append({"name": c["name"], "kind": c["kind"], "status": c["status"], "detail": c["detail"],
                         "severity": c["severity"], "uptime": s.get("uptime"),
                         "incidents": s.get("incidents", 0), "strip": s.get("strip", [])})
        return {"host": (cur or {}).get("host", socket.gethostname()), "time": (cur or {}).get("time"),
                "uptime_hours": (cur or {}).get("uptime_hours"), "interval": a.interval, "checks": rows,
                "availability": an["availability"], "incidents": an["incidents"], "scans": an["scans"],
                "fixable": fixable, "fix_output": state["fix"], "busy": state["busy"],
                "slot_start": int((time.time() - hist.hours * 3600) * 1000)}

    def loop():
        while True:
            try:
                do_scan()
            except Exception as ex:  # noqa: BLE001 - keep the dashboard alive
                print(f"scan failed: {ex}")
            time.sleep(a.interval)

    class Handler(BaseHTTPRequestHandler):
        def send(self, code, body, ctype="application/json"):
            data = body.encode("utf-8") if isinstance(body, str) else body
            self.send_response(code)
            self.send_header("Content-Type", f"{ctype}; charset=utf-8")
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self):
            if self.headers.get("Host") not in hosts:
                return self.send(403, '{"error": "bad host"}')
            if self.path == "/":
                self.send(200, DASHBOARD_HTML.replace("__TOKEN__", token), "text/html")
            elif self.path == "/api/status":
                self.send(200, json.dumps(status()))
            elif self.path == "/report" and REPORT.exists():
                self.send(200, REPORT.read_bytes(), "text/html")
            else:
                self.send(404, '{"error": "not found"}')

        def do_POST(self):
            if self.headers.get("Host") not in hosts or not secrets.compare_digest(
                    self.headers.get("X-Token", ""), token):
                return self.send(403, '{"error": "forbidden"}')
            if self.path == "/api/scan":
                state["busy"] = "scan"
                try:
                    do_scan()
                finally:
                    state["busy"] = None
                self.send(200, '{"ok": true}')
            elif self.path == "/api/fix":
                self.send(200, json.dumps({"output": do_fix()}))
            else:
                self.send(404, '{"error": "not found"}')

        def log_message(self, *args):
            pass

    threading.Thread(target=loop, daemon=True).start()
    print(f"Dashboard: http://127.0.0.1:{a.port}  (scans every {a.interval}s, Ctrl+C to stop)")
    ThreadingHTTPServer(("127.0.0.1", a.port), Handler).serve_forever()


DASHBOARD_HTML = """<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1"><title>System Health</title>
<style>
:root{--bg:#fcfcfb;--card:#fff;--ink:#1f2328;--muted:#5d6670;--line:#dde2e7;--none:#e4e7eb;
 --good:#0ca30c;--bad:#d03b3b;--accent:#1f6feb}
@media (prefers-color-scheme:dark){:root{--bg:#1a1a19;--card:#222221;--ink:#e8eaed;--muted:#a0a7b0;
 --line:#34373b;--none:#3a3b3d}}
*{box-sizing:border-box} body{margin:0;background:var(--bg);color:var(--ink);font:14px system-ui,sans-serif}
header{display:flex;align-items:center;gap:10px;padding:14px 24px;border-bottom:1px solid var(--line);flex-wrap:wrap}
h1{font-size:18px;margin:0;flex:1}
.live{color:var(--muted);font-size:13px;margin-right:6px}
.dot{display:inline-block;width:8px;height:8px;border-radius:50%;background:var(--good);margin-right:6px;
 animation:pulse 2s infinite} .off .dot{background:var(--bad);animation:none}
@keyframes pulse{50%{opacity:.25}}
button{font:600 14px system-ui;padding:8px 16px;border-radius:6px;border:1px solid var(--line);
 background:var(--card);color:var(--ink);cursor:pointer} button.primary{background:var(--accent);
 border-color:var(--accent);color:#fff} button:disabled{opacity:.45;cursor:default}
main{padding:20px 24px;max-width:1200px;margin:auto}
.tiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:12px;margin-bottom:20px}
.tile{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:14px 16px}
.k{color:var(--muted);font-size:12px;text-transform:uppercase;letter-spacing:.04em}
.v{font-size:30px;font-weight:650;margin-top:4px;font-variant-numeric:tabular-nums}
.sub{color:var(--muted);font-size:12px;margin-top:2px}
.pill{display:inline-flex;align-items:center;gap:5px;font-weight:600;font-size:12px;padding:2px 9px;
 border-radius:999px;color:#fff;white-space:nowrap} .pill.UP{background:var(--good)} .pill.DOWN,.pill.UNKNOWN{background:var(--bad)}
.v .pill{font-size:20px;padding:4px 14px}
table{width:100%;border-collapse:collapse;background:var(--card);border:1px solid var(--line);border-radius:8px;overflow:hidden}
th,td{padding:9px 12px;border-bottom:1px solid var(--line);text-align:left;vertical-align:middle}
th{color:var(--muted);font-weight:600;font-size:12px} td.n,th.n{text-align:right;font-variant-numeric:tabular-nums}
.detail{color:var(--muted)} .strip{display:flex;gap:2px} .strip i{width:5px;height:16px;border-radius:2px;background:var(--none)}
.strip i.u{background:var(--good)} .strip i.d{background:var(--bad)}
.legend{color:var(--muted);font-size:12px;margin:8px 0 0;display:flex;gap:14px}
.legend i{display:inline-block;width:10px;height:10px;border-radius:2px;margin-right:4px;vertical-align:-1px}
pre{background:var(--card);border:1px solid var(--line);padding:12px;border-radius:8px;white-space:pre-wrap;font-size:12px}
</style></head><body>
<header><h1 id="host">System Health</h1>
 <span id="live" class="live"><span class="dot"></span><span id="livetxt">connecting...</span></span>
 <button id="scanbtn">Scan now</button><button id="fixbtn" class="primary">Fix now</button>
 <button onclick="window.open('/report')">Report</button></header>
<main>
 <div class="tiles">
  <div class="tile"><div class="k">Status</div><div class="v" id="t-status">-</div><div class="sub" id="t-machine"></div></div>
  <div class="tile"><div class="k">Checks up</div><div class="v" id="t-up">-</div><div class="sub" id="t-down"></div></div>
  <div class="tile"><div class="k">Availability, 24 h</div><div class="v" id="t-avail">-</div><div class="sub" id="t-scans"></div></div>
  <div class="tile"><div class="k">Incidents, 24 h</div><div class="v" id="t-inc">-</div><div class="sub">times a check went from UP to DOWN</div></div>
 </div>
 <table><thead><tr><th>Status</th><th>Check</th><th>Detail</th><th class="n">Uptime 24 h</th>
  <th class="n">Incidents</th><th>Last 24 h</th></tr></thead><tbody id="rows"></tbody></table>
 <div class="legend"><span><i style="background:var(--good)"></i>UP</span><span><i style="background:var(--bad)"></i>DOWN at least once</span>
  <span><i style="background:var(--none)"></i>no scan</span><span>each cell = 30 minutes, newest on the right</span></div>
 <div id="fixout"></div>
</main>
<script>
const TOKEN = "__TOKEN__";
const $ = id => document.getElementById(id);
const esc = s => String(s ?? "").replace(/[&<>"]/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;"}[c]));
const pill = (s, label = s) => `<span class="pill ${s}">${s === "UP" ? "&#10004;" : "&#10006;"} ${label}</span>`;
const hhmm = ms => new Date(ms).toLocaleTimeString([], {hour: "2-digit", minute: "2-digit"});
let data = null;

async function refresh() {
  try {
    data = await (await fetch("/api/status", {cache: "no-store"})).json();
    $("live").className = "live"; draw(data);
  } catch (e) {
    $("live").className = "live off"; $("livetxt").textContent = "Disconnected: is the app running?";
  }
}

function draw(d) {
  $("host").textContent = "System Health: " + d.host;
  if (!d.time) { $("livetxt").textContent = "First scan running..."; return; }
  const ago = Math.max(0, Math.round((Date.now() - new Date(d.time)) / 1000));
  $("livetxt").textContent = d.busy ? (d.busy === "fix" ? "Fixing..." : "Scanning...")
                                    : `Live · last scan ${ago}s ago · every ${d.interval}s`;
  const down = d.checks.filter(c => c.status !== "UP");
  $("t-status").innerHTML = down.length ? pill("DOWN", down.length + " DOWN") : pill("UP", "ALL UP");
  $("t-machine").textContent = `machine up ${d.uptime_hours} h`;
  $("t-up").textContent = `${d.checks.length - down.length} / ${d.checks.length}`;
  $("t-down").textContent = down.length ? "Down: " + down.map(c => c.name).join(", ") : "nothing down";
  $("t-avail").textContent = d.availability == null ? "-" : d.availability + "%";
  $("t-scans").textContent = `share of ${d.scans} scans with everything UP`;
  $("t-inc").textContent = d.incidents;
  const slot = 30 * 60 * 1000;
  const rows = [...d.checks].sort((a, b) => (a.status === "UP") - (b.status === "UP"));
  $("rows").innerHTML = rows.map(c => `<tr><td>${pill(c.status)}</td><td><b>${esc(c.name)}</b>
    <div class="detail">${esc(c.kind)} · ${esc(c.severity)}</div></td><td class="detail">${esc(c.detail)}</td>
    <td class="n">${c.uptime == null ? "-" : c.uptime + "%"}</td><td class="n">${c.incidents}</td>
    <td><div class="strip">${c.strip.map((s, i) => `<i class="${s === true ? "u" : s === false ? "d" : ""}"
      title="${hhmm(d.slot_start + i * slot)}-${hhmm(d.slot_start + (i + 1) * slot)}: ${s === true ? "UP" : s === false ? "DOWN at least once" : "no scan"}"></i>`).join("")}</div></td></tr>`).join("");
  $("scanbtn").disabled = !!d.busy;
  $("fixbtn").disabled = !!d.busy || !d.fixable;
  $("fixbtn").textContent = d.fixable ? `Fix now (${d.fixable})` : "Fix now";
  $("fixbtn").title = d.fixable ? "Run sysfix --apply, then re-scan" : "Nothing auto-fixable is DOWN";
  if (d.fix_output) $("fixout").innerHTML = `<h3>Last fix run</h3><pre>${esc(d.fix_output)}</pre>`;
}

async function act(path, btn, label) {
  btn.disabled = true; const old = btn.textContent; btn.textContent = label;
  try { await fetch(path, {method: "POST", headers: {"X-Token": TOKEN}}); }
  finally { btn.textContent = old; refresh(); }
}
$("scanbtn").onclick = () => act("/api/scan", $("scanbtn"), "Scanning...");
$("fixbtn").onclick = () => act("/api/fix", $("fixbtn"), "Fixing...");
refresh(); setInterval(refresh, 3000);
</script></body></html>"""


if __name__ == "__main__":
    main()
