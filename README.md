# system-health-scanner

A small, read-only tool that checks whether a Windows machine and its apps are up and running, then writes an HTML report and serves a local dashboard.

- **Health:** CPU, memory and disk usage against limits you set
- **Apps intact:** Windows services, processes, TCP ports and HTTP endpoints, each reported UP or DOWN
- **Report:** overall status, what to fix first (by severity), changes since the last scan, and all checks
- **Automation-friendly:** exit code 0 means everything is UP, 1 means something is DOWN

It's a single Python file with one dependency (PyYAML). It works offline, uses no AI and has no paid services. It only reads system state and never changes it.

## Requirements

- Windows 10 or 11 with PowerShell 5.1+
- Python 3.9+

```powershell
pip install -r requirements.txt
```

## Usage

```powershell
python sysscan.py scan        # run checks, write results\report.html
python sysscan.py report      # rebuild the report from the last scan
python sysscan.py dashboard   # http://127.0.0.1:8765, rescans every 60 s
python sysscan.py dashboard --interval 30 --port 9000
```

## Configure

Edit `apps.yml`:

```yaml
health:
  cpu_max: 90
  memory_max: 90
  disk_max: 90
  disks: ["C:\\"]

apps:
  - service: Winmgmt                      # Windows service name (Get-Service)
  - process: nginx                        # process name, .exe optional
  - port: 5432                            # TCP port on localhost
  - port: 443
    host: 10.0.0.5                        # only scan machines you own or are authorized to scan
  - http: http://localhost:8080/health
    expect: 200
    severity: critical                    # critical / high / medium / low
```

## Auto-fix with sysfix

`sysfix.py` reads the latest sysscan report and fixes what is DOWN, most severe first. It then re-runs sysscan to verify, so the report's "Changes since last scan" shows what RECOVERED.

```powershell
python sysfix.py            # dry run: shows what it would fix and changes nothing
python sysfix.py --apply    # run the fixes, then re-scan (exit 0 = all UP)
```

| Problem | Fix |
|---|---|
| Service down | `sc.exe start <name>`, automatic (most services need an admin window) |
| Process, port or HTTP down | the `fix:` command on that entry in `apps.yml` |
| CPU, memory or disk over limit | not auto-fixed; listed as MANUAL with advice |

```yaml
  - http: http://localhost:8080/health
    fix: Start-Process "C:\path\to\my-web-app.exe"
    fix_wait: 10        # seconds before re-checking
```

Every fix attempt is logged to `results/fixes.log`.

## Schedule it

Every 15 minutes with Task Scheduler:

```powershell
schtasks /Create /SC MINUTE /MO 15 /TN sysscan /TR "python C:\path\to\sysscan.py scan"
# scan and self-heal every 15 minutes:
schtasks /Create /SC MINUTE /MO 15 /TN sysfix /TR "cmd /c python C:\path\to\sysscan.py scan & python C:\path\to\sysfix.py --apply"
```

In CI (Jenkins or GitHub Actions on a Windows runner), run `python sysscan.py scan`. A non-zero exit fails the job; publish `results/report.html` as an artifact.

## Data

Scans are saved as `results/scan-*.json`, and the newest 200 are kept. The dashboard binds to `127.0.0.1` only.

## License

MIT
