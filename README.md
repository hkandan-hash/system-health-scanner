# system-health-scanner

Checks whether a Windows machine and its apps are up and running, writes an HTML report, serves a local dashboard, and can fix what is DOWN automatically.

- **Health:** CPU, memory and disk usage against limits you set
- **Apps intact:** Windows services, processes, TCP ports and HTTP endpoints, each reported UP or DOWN
- **Report:** overall status, what to fix first (by severity), changes since the last scan, and all checks
- **Self-healing:** `sysfix.py` reads the report, fixes what is DOWN, and re-scans to prove it worked
- **Automation-friendly:** exit code 0 means everything is UP, 1 means something is DOWN

It's two small Python files with one dependency (PyYAML), and works offline with no AI or paid services. `sysscan.py` only reads system state. `sysfix.py` changes things only when you run it with `--apply`.

## How it works

```
apps.yml ──► sysscan.py scan ──► results/scan-*.json + report.html ──► dashboard (127.0.0.1:8765)
                                          │
                                          ▼
                                 sysfix.py --apply ──► runs fixes ──► re-scan ──► RECOVERED in report
```

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

python sysfix.py              # dry run: shows what it would fix and changes nothing
python sysfix.py --apply      # run the fixes, then re-scan (exit 0 = all UP)
```

Example scan:

```
UP       Windows Defender               service status: Running
UP       Wi-Fi                          service status: Running
UP       OneDrive sync                  running
DOWN     sysscan dashboard              no response (connection refused)
```

Then `python sysfix.py --apply` relaunches the dashboard, and the re-scan shows `UP  sysscan dashboard  HTTP 200 in 18 ms`.

## What the included apps.yml monitors

| Group | Checks | Auto-fix |
|---|---|---|
| Security | Windows Defender (critical) | service restart* |
| Network | Wi-Fi, DHCP client, DNS client | service restart* |
| Core Windows | Event Log, WMI, Windows Explorer | service restart*; Explorer relaunch |
| Everyday apps | Windows Audio, Office Click-to-Run, OneDrive | service restart*; OneDrive relaunch |
| This tool | sysscan dashboard (HTTP) | relaunch |
| Health | CPU, memory, disk C:\ | manual (advice only) |

\* `sc.exe start <name>`: most Windows services need sysfix to run from an admin window.

## Configure

Edit `apps.yml`. Each entry needs one of `service`, `process`, `port` or `http`:

```yaml
health:
  cpu_max: 90
  memory_max: 90
  disk_max: 90
  disks: ["C:\\"]

apps:
  - service: WinDefend                    # Windows service name (Get-Service)
    severity: critical                    # critical / high / medium / low (default high)
  - process: nginx                        # process name, .exe optional
    fix: Start-Process "C:\nginx\nginx.exe" -WorkingDirectory "C:\nginx"
  - port: 5432                            # TCP port on localhost
  - port: 443
    host: 10.0.0.5                        # only scan machines you own or are authorized to scan
  - http: http://localhost:8080/health
    expect: 200
    fix: Start-Process "C:\path\to\my-web-app.exe"
    fix_wait: 10                          # seconds before re-checking (default 5)
```

`fix:` is a PowerShell command, run from this folder, so relative paths work. Services need no `fix:` because sysfix restarts them. Every fix attempt is logged to `results/fixes.log`.

## Schedule it

Scan and self-heal every 15 minutes with Task Scheduler:

```powershell
schtasks /Create /SC MINUTE /MO 15 /TN sysfix /TR "cmd /c python C:\path\to\sysscan.py scan & python C:\path\to\sysfix.py --apply"
```

In CI (Jenkins or GitHub Actions on a Windows runner), run `python sysscan.py scan`. A non-zero exit fails the job; publish `results/report.html` as an artifact.

## Data and safety

- Scans are saved as `results/scan-*.json`; the newest 200 are kept. `results/` is git-ignored.
- The dashboard binds to `127.0.0.1` only and is never exposed to the network.
- sysscan runs only read-only commands (`Get-Service`, `Get-Process`, `Get-CimInstance`, socket and HTTP checks).
- sysfix runs only service starts and the `fix:` commands you write yourself, and only with `--apply`.

## Roadmap: what to build next

| # | Feature | Why |
|---|---|---|
| 1 | `sysfix.py --install-schedule`: one command sets up the 15-minute scan and fix | Makes self-healing automatic without copying a `schtasks` line |
| 2 | Retry limit: stop retrying a fix after N failures and mark it `NEEDS HUMAN` | Prevents a broken fix from looping every run |
| 3 | Alerts when something stays DOWN: Windows notification, email (SMTP) or a Teams/Slack webhook | You hear about problems without opening the dashboard |
| 4 | Dashboard "Fix now" button and a 24-hour UP/DOWN history strip | Fix from the UI and see flapping at a glance |
| 5 | Remote machines: services and processes on other Windows PCs you own, over WinRM (ports and HTTP already work with `host:`) | Monitor several machines from one dashboard |
| 6 | Unit tests and a GitHub Actions workflow on `windows-latest` | Every change is verified automatically |
| 7 | Optional AI summary of the report, run locally (Ollama), off by default | Plain-English explanations with no cost and no data leaving the machine |

## License

MIT
