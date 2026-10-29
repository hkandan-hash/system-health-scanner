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
import contextlib
import datetime as dt
import io
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


STATE = RESULTS / "fix-state.json"  # consecutive failed fix attempts per check
MAX_TRIES = 3
TASK = "SystemHealthScanner"


def load_state():
    try:
        return json.loads(STATE.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def plan(scan, items, state=None):
    """Split DOWN checks into auto-fixable and manual. A check whose fix failed MAX_TRIES times
    in a row becomes manual (NEEDS HUMAN) until it is UP again."""
    state = load_state() if state is None else state
    todo, manual = [], []
    bad = sorted((c for c in scan["checks"] if c["status"] != "UP"),
                 key=lambda c: SEV_ORDER.get(c["severity"], 9))
    for c in bad:
        item = items.get(c["key"], {})
        tries = int(item.get("max_tries", MAX_TRIES))
        if state.get(c["key"], 0) >= tries:
            manual.append({**c, "fix": f"NEEDS HUMAN: auto-fix failed {tries} times in a row. {c['fix']}"})
            continue
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
    ap.add_argument("--scan", action="store_true", help="run a fresh scan first instead of using the last report")
    ap.add_argument("--install-schedule", type=int, metavar="MINUTES",
                    help="create a Windows scheduled task that runs --scan --apply every N minutes")
    ap.add_argument("--uninstall-schedule", action="store_true", help="remove that scheduled task")
    a = ap.parse_args(argv)

    if a.install_schedule or a.uninstall_schedule:
        return schedule(a.install_schedule)
    if a.scan:
        with contextlib.redirect_stdout(io.StringIO()):
            sysscan.run_scan(a.config)

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
    code = sysscan.run_scan(a.config)

    # Count consecutive failures; a check that is UP (fixed by us or by hand) starts over.
    state, after = load_state(), {c["key"]: c["status"] for c in latest_scan()["checks"]}
    for c, _, _ in todo:
        if after.get(c["key"]) != "UP":
            state[c["key"]] = state.get(c["key"], 0) + 1
    state = {k: n for k, n in state.items() if after.get(k) != "UP"}
    STATE.write_text(json.dumps(state, indent=2), encoding="utf-8")
    return code


def schedule(minutes):
    """Install or remove the Windows scheduled task (runs as the current user)."""
    if not minutes:
        r = subprocess.run(["schtasks", "/Delete", "/TN", TASK, "/F"], capture_output=True, text=True, errors="replace")
        print(r.stdout.strip() or r.stderr.strip())
        return r.returncode
    if getattr(sys, "frozen", False):
        cmd = f'"{sys.executable}" fix --scan --apply'
    else:
        py = Path(sys.executable).with_name("pythonw.exe")  # no console window every run
        cmd = f'"{py if py.exists() else sys.executable}" "{HERE / "sysfix.py"}" --scan --apply'
    r = subprocess.run(["schtasks", "/Create", "/SC", "MINUTE", "/MO", str(minutes), "/TN", TASK, "/TR", cmd, "/F"],
                       capture_output=True, text=True, errors="replace")
    print(r.stdout.strip() or r.stderr.strip())
    if r.returncode == 0:
        print(f"Every {minutes} min: {cmd}\nRemove with: --uninstall-schedule")
    return r.returncode


if __name__ == "__main__":
    sys.exit(main())
