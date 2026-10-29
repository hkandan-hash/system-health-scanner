"""sysscan: check that this Windows machine and its apps are up, then write an HTML report.

Usage:
  python sysscan.py scan                     run checks, write report, exit 1 if anything is not UP
  python sysscan.py report                   rebuild the report from the last saved scan
  python sysscan.py dashboard [--interval 60] [--port 8765]
"""
import argparse
import ctypes
import datetime as dt
import html
import json
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

HERE = Path(__file__).resolve().parent
RESULTS = HERE / "results"
REPORT = RESULTS / "report.html"
KEEP_SCANS = 200
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
        capture_output=True, text=True, encoding="utf-8", timeout=90,
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


def render(cur, prev, refresh=None):
    e = html.escape
    bad = sorted((c for c in cur["checks"] if c["status"] != "UP"),
                 key=lambda c: (SEV_ORDER.get(c["severity"], 9), c["kind"] != "health"))
    up = len(cur["checks"]) - len(bad)
    overall = "ALL UP" if not bad else f"{len(bad)} PROBLEM{'S' if len(bad) > 1 else ''}"
    color = "#1a7f37" if not bad else "#cf222e"
    fixes = "".join(f"<li><b>{e(c['name'])}</b> <span class=sev>{e(c['severity'])}</span>: "
                    f"{e(c['detail'])}<br><code>{e(c['fix'])}</code></li>" for c in bad) or "<li>Nothing to fix.</li>"
    rows = "".join(f"<tr><td class={c['status']}>{c['status']}</td><td>{e(c['name'])}</td>"
                   f"<td>{e(c['kind'])}</td><td>{e(c['detail'])}</td></tr>" for c in cur["checks"])
    diff = "".join(f"<li>{e(x)}</li>" for x in changes(cur, prev))
    meta = f'<meta http-equiv="refresh" content="{refresh}">' if refresh else ""
    return f"""<!DOCTYPE html><html><head><meta charset="utf-8">{meta}<title>sysscan: {e(cur['host'])}</title>
<style>body{{font:15px system-ui,sans-serif;max-width:960px;margin:2em auto;padding:0 1em;color:#1f2328}}
h1 span{{color:{color}}} table{{border-collapse:collapse;width:100%}} td,th{{border-bottom:1px solid #d0d7de;padding:6px;text-align:left}}
.UP{{color:#1a7f37;font-weight:600}} .DOWN,.UNKNOWN{{color:#cf222e;font-weight:600}} code{{background:#f6f8fa;padding:2px 4px}}
.sev{{font-size:12px;background:#eee;padding:1px 6px;border-radius:8px}} li{{margin-bottom:8px}}</style></head><body>
<h1>{e(cur['host'])}: <span>{overall}</span></h1>
<p>Scanned {e(cur['time'])} · {up}/{len(cur['checks'])} checks up · machine up {cur['uptime_hours']} h</p>
<h2>Fix first</h2><ol>{fixes}</ol>
<h2>Changes since last scan</h2><ul>{diff}</ul>
<h2>All checks</h2><table><tr><th>Status</th><th>Check</th><th>Type</th><th>Detail</th></tr>{rows}</table>
</body></html>"""


def load_cfg(path):
    return yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}


def main():
    ap = argparse.ArgumentParser(description="Check that this machine and its apps are up.")
    ap.add_argument("command", choices=["scan", "report", "dashboard"])
    ap.add_argument("--config", default=str(HERE / "apps.yml"))
    ap.add_argument("--interval", type=int, default=60, help="dashboard: seconds between scans")
    ap.add_argument("--port", type=int, default=8765, help="dashboard: local port")
    a = ap.parse_args()

    if a.command == "report":
        cur, prev = saved_scans()
        if cur is None:
            sys.exit("No saved scans yet. Run: python sysscan.py scan")
        REPORT.write_text(render(cur, prev), encoding="utf-8")
        print(f"Report: {REPORT}")
        return

    cfg = load_cfg(a.config)
    if a.command == "scan":
        cur = scan(cfg)
        _, prev = saved_scans()
        REPORT.write_text(render(cur, prev), encoding="utf-8")
        for c in cur["checks"]:
            print(f"{c['status']:8} {c['name']:30} {c['detail']}")
        print(f"Report: {REPORT}")
        sys.exit(0 if all(c["status"] == "UP" for c in cur["checks"]) else 1)

    # dashboard: rescan in the background, serve the latest report on localhost only
    page = {"html": "<p>First scan running...</p>"}

    def loop():
        while True:
            cur = scan(load_cfg(a.config))
            _, prev = saved_scans()
            page["html"] = render(cur, prev, refresh=a.interval)
            REPORT.write_text(render(cur, prev), encoding="utf-8")
            time.sleep(a.interval)

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            body = page["html"].encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            pass

    threading.Thread(target=loop, daemon=True).start()
    print(f"Dashboard: http://127.0.0.1:{a.port}  (rescans every {a.interval}s, Ctrl+C to stop)")
    ThreadingHTTPServer(("127.0.0.1", a.port), Handler).serve_forever()


if __name__ == "__main__":
    main()
