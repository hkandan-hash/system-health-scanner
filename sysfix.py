"""sysfix: read the latest sysscan report and fix what is DOWN.

Usage:
  python sysfix.py            show what would be fixed (changes nothing)
  python sysfix.py --apply    run the fixes, then re-scan with sysscan to verify

Fixes:
  service  -> sc.exe start <name>  (automatic; most services need an admin window)
  any app  -> the `fix:` command you set on that entry in apps.yml
  health (CPU/memory/disk) -> not auto-fixed; shown as manual
"""
import argparse
import datetime as dt
import json
import subprocess
import sys
import time
from pathlib import Path

import yaml

import sysscan
from sysscan import HERE, NO_WINDOW, RESULTS, SEV_ORDER


def latest_scan():
    files = sorted(RESULTS.glob("scan-*.json"))
    if not files:
        sys.exit("No sysscan report found. Run: python sysscan.py scan")
    return json.loads(files[-1].read_text(encoding="utf-8"))


def fixes_from_config(path):
    """Map each apps.yml entry to sysscan's check key, so report rows can be matched to fix commands."""
    cfg = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
    out = {}
    for item in cfg.get("apps") or []:
        kind = next((k for k in ("service", "process", "port", "http") if k in item), None)
        if kind is None:
            continue
        target = f"{item.get('host', '127.0.0.1')}:{item['port']}" if kind == "port" else str(item[kind])
        out[f"{kind}:{target}"] = item
    return out


def plan(scan, items):
    todo, manual = [], []
    bad = sorted((c for c in scan["checks"] if c["status"] != "UP"),
                 key=lambda c: SEV_ORDER.get(c["severity"], 9))
    for c in bad:
        item = items.get(c["key"], {})
        if item.get("fix"):
            cmd = ["powershell", "-NoProfile", "-NonInteractive", "-Command", str(item["fix"])]
        elif c["kind"] == "service":
            cmd = ["sc.exe", "start", str(item.get("service", c["key"].split(":", 1)[1]))]
        else:
            manual.append(c)
            continue
        todo.append((c, cmd, int(item.get("fix_wait", 5))))
    return todo, manual


def show(cmd):
    return cmd[-1] if cmd[0] == "powershell" else " ".join(cmd)


def main(argv=None):
    """Returns 0 if everything is UP afterwards (or nothing to fix), else 1."""
    ap = argparse.ArgumentParser(description="Fix what the latest sysscan report shows as DOWN.")
    ap.add_argument("--apply", action="store_true", help="actually run the fixes")
    ap.add_argument("--config", default=str(HERE / "apps.yml"))
    a = ap.parse_args(argv)

    scan = latest_scan()
    todo, manual = plan(scan, fixes_from_config(a.config))
    print(f"Report from {scan['time']} on {scan['host']}: {len(todo)} auto-fixable, {len(manual)} manual")
    for c, cmd, _ in todo:
        print(f"  FIX     {c['name']:28} -> {show(cmd)}")
    for c in manual:
        print(f"  MANUAL  {c['name']:28} -> {c['fix']}")
    if not todo:
        return 0 if not manual else 1
    if not a.apply:
        print("\nDry run, nothing changed. Re-run with --apply to fix.")
        return 1

    log = RESULTS / "fixes.log"
    for c, cmd, _ in todo:
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, errors="replace", timeout=120, cwd=HERE,
                               creationflags=NO_WINDOW)
            ok, out = r.returncode == 0, (r.stdout + r.stderr).strip()
        except (OSError, subprocess.TimeoutExpired) as e:
            ok, out = False, str(e)
        print(f"  {'RAN' if ok else 'FAILED':7} {c['name']:28} {out.splitlines()[-1] if out else ''}"[:160])
        with log.open("a", encoding="utf-8") as f:
            f.write(json.dumps({"time": dt.datetime.now().isoformat(timespec="seconds"), "check": c["key"],
                                "cmd": show(cmd), "ok": ok, "output": out[-500:]}) + "\n")

    time.sleep(max(w for _, _, w in todo))
    print("\nRe-scanning to verify...")
    return sysscan.run_scan(a.config)


if __name__ == "__main__":
    sys.exit(main())
