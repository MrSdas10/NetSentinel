# NetSentinel

**NetSentinel** is a lightweight, passive Network Intrusion Detection System
(NIDS) written in Python. It reads live traffic from an authorized network
interface or analyzes an existing PCAP file, applies configurable detection
rules, and stores structured alerts and reports.

NetSentinel is intended for defensive monitoring, coursework, and controlled
lab environments. Only capture or scan networks and systems that you own or
have explicit permission to test.

## Features

- Live packet capture with Scapy.
- Offline PCAP analysis.
- TCP SYN destination-port diversity detection (possible port scan).
- UDP destination-port diversity detection.
- ICMP echo-request rate anomaly detection.
- ARP IP-to-MAC mapping conflict detection.
- DNS query-rate and NXDOMAIN anomaly detection.
- Optional baseline learning and anomaly comparison.
- JSON, CSV, and HTML reports.
- JSONL alert history in `alerts/alerts.jsonl`.
- Timestamped runtime logs in `logs/`, for example
  `logs/NetSentinel_Log_2026-10-13_13-56-57.txt`.
- Historical dashboard generated from saved reports and alerts.

## Project layout

```text
NetSentinel/
├── main.py                 # CLI entry point
├── config.json             # Detection and output configuration
├── requirements.txt        # Python dependency list
├── alert_manager.py        # Detection rules and alert handling
├── capture.py              # Live and offline capture adapters
├── parsers.py              # Packet normalization
├── reporter.py             # JSON, CSV, HTML, and JSONL output
├── runtime_logger.py       # Per-run timestamped logging
├── dashboard.py            # Historical dashboard generation
├── make_test_pcap.py       # Synthetic offline test traffic generator
├── alerts/                 # Alert history
├── reports/                # Generated reports and dashboards
├── data/                   # PCAPs and baseline state
└── logs/                   # Configured application log
```

## Architecture Diagram

NetSentinel keeps packet acquisition, parsing, detection, and reporting
separate so that the same detection engine can be used for live traffic and
offline PCAPs:

```text
                           +----------------------+
                           |      main.py CLI      |
                           | config / mode / logs |
                           +----------+-----------+
                                      |
                    +-----------------+-----------------+
                    |                                   |
          +---------v---------+               +---------v---------+
          |   LiveCapture     |               |  OfflineCapture   |
          | Scapy interface   |               |    PCAP reader    |
          +---------+---------+               +---------+---------+
                    |                                   |
                    +-----------------+-----------------+
                                      |
                              +-------v-------+
                              | PacketProcessor|
                              | capture stats  |
                              | parse errors   |
                              +-------+--------+
                                      |
                              +-------v-------+
                              |   parsers.py  |
                              | ParsedPacket  |
                              +-------+-------+
                                      |
                              +-------v-------+
                              | AlertManager  |
                              | TCP / UDP /   |
                              | ICMP / ARP /  |
                              | DNS rules     |
                              +---+-------+---+
                                  |       |
                    +-------------+       +----------------+
                    |                                      |
          +---------v---------+                  +---------v---------+
          | Baseline          |                  | Alert callback    |
          | learning/state    |                  | JSONL persistence |
          +---------+---------+                  +-------------------+
                    |
          +---------v--------------------------------------+
          | reporter.py                                    |
          | JSON + CSV + per-session HTML reports           |
          +----------------------+--------------------------+
                                 |
                    +------------v-------------+
                    | dashboard.py             |
                    | historical HTML dashboard|
                    +--------------------------+

                 runtime_logger.py -> timestamped root .txt log
                 config.json       -> thresholds and output paths
```

The live and offline paths converge at `PacketProcessor`, which means that
offline analysis exercises the same parser and detection rules used during a
live capture. The dashboard reads persisted reports and alerts after capture;
it is not part of the packet-processing path.

# 1. Setup

## Prerequisites

If you have not already opened a local checkout:

```bash
git clone https://github.com/MrSdas10/NetSentinel
cd NetSentinel
```

- Python 3.11 or newer.
- Administrator/root privileges for most live-capture configurations.
- Scapy, installed from `requirements.txt`.
- A packet-capture provider:
  - **Windows:** install [Npcap](https://npcap.com), preferably with WinPcap
    compatibility mode.
  - **Linux:** install `libpcap-dev` and run capture with `sudo`, or grant
    the Python interpreter the required capture capabilities.
  - **macOS:** install `libpcap`; `sudo` is normally required for capture.

## Windows setup

Open PowerShell in the repository directory:

```powershell
py -3 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

If PowerShell blocks activation, either allow scripts for the current user or
run the interpreter directly:

```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
```

Verify the installation and inspect the CLI:

```powershell
python -c "import scapy; print(scapy.__version__)"
python main.py --help
python main.py --list-interfaces
python main.py --show-config
```

## Linux setup

```bash
sudo apt-get update
sudo apt-get install -y python3-venv python3-dev libpcap-dev
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python main.py --help
sudo python main.py --list-interfaces
```

## Configuration

`config.json` contains the rule thresholds and output locations. The default
rules include:

| Rule | Default trigger |
| --- | --- |
| `TCP-001` | 20 distinct TCP SYN destination ports from one source in 60 seconds |
| `UDP-001` | 15 distinct UDP destination ports from one source in 60 seconds |
| `ICMP-001` | 50 ICMP echo requests from one source in 30 seconds |
| `ARP-001` | An IP address observed with conflicting MAC addresses |
| `DNS-001` | 100 DNS queries from one source in 60 seconds |
| `DNS-002` | 20 NXDOMAIN responses from one source in 60 seconds |

Thresholds should be adjusted for the size and normal traffic profile of the
lab. Do not lower them blindly on a busy production network.

Every invocation creates a unique timestamped runtime log in `logs/`.
`--verbose` changes the runtime log level to `DEBUG`; it does not change the
detection thresholds.

# 2. Offline use: captured data, stored logs, and test data

Offline analysis is the safest way to learn NetSentinel because it does not
touch a live interface. It is also useful for regression testing and
investigating a capture collected with permission.

## Analyze the included synthetic PCAP

The repository includes `data/test_traffic.pcap`. If it is missing or you want
to regenerate it:

```powershell
python make_test_pcap.py
```

```bash
python make_test_pcap.py
```

The generator creates synthetic TCP, UDP, ICMP, ARP, and DNS traffic. It does
not send packets onto the network.

Analyze it and write JSON, CSV, and HTML reports:

```powershell
python main.py --offline data\test_traffic.pcap --report
```

```bash
python main.py --offline data/test_traffic.pcap --report
```

The resulting files are written under `reports/`. Alerts are appended to
`alerts/alerts.jsonl`, and the per-run runtime log is written in `logs/`.
PCAP paths may be absolute or relative to the repository.

## Analyze a previously captured PCAP

```powershell
python main.py --offline "C:\captures\authorized-lab-session.pcap" --report
```

Use a copy of the capture when possible. NetSentinel reads the PCAP; it does
not modify the original file.

## Review existing logs and reports

The configured application log is normally `logs/netsentinel.log`. Each run
also has a separate timestamped log in `logs/`. Reports are stored as:

- `reports/netsentinel_report_*.json` — machine-readable report data.
- `reports/netsentinel_report_*.csv` — tabular alert data.
- `reports/netsentinel_report_*.html` — per-session report.
- `alerts/alerts.jsonl` — append-only alert history.

Generate a historical dashboard from all stored JSON reports and JSONL alerts:

```powershell
python main.py --visualize
```

```bash
python main.py --visualize
```

The dashboard is written to `reports/netsentinel_dashboard_*.html`. Open that
file in a browser to review protocol totals, severity and rule activity,
source-IP counts, session history, and latest-versus-previous session
comparison.

## Offline verification checklist

After an offline run, verify:

1. The command exits successfully.
2. A new timestamped `logs/NetSentinel_Log_*.txt` file exists.
3. A JSON, CSV, and HTML report exist when `--report` is supplied.
4. `alerts/alerts.jsonl` contains structured JSON lines.
5. `python main.py --visualize` creates a dashboard without needing a live
   network interface.

# 3. Live use and controlled test guide

Live capture should be performed only on an isolated, authorized lab network.
The recommended layout is two VMs connected to the same host-only or
internal-only virtual switch:

```text
VM 1: NetSentinel sensor (Linux or the Machine you are running this script)   192.168.56.10 (Example IP)
VM 2: test generator/target machine(ubuntu or any other)    192.168.56.20 (example Ip)
```

Do not use bridged networking for experiments unless the network owner has
approved it. Host-only/internal networking prevents test traffic from
reaching unrelated systems.

## Start a live capture

First list interfaces and identify the interface connected to the lab network:

```powershell
python main.py --list-interfaces
```

Start a bounded capture with reports and verbose runtime logging:

```powershell
python main.py --interface "Ethernet" --duration 120 --report --verbose
```

On Linux, use the interface name returned by `ip link` and run with the
required privileges:

```bash
sudo python main.py --interface eth1 --duration 120 --report --verbose
```

To stop an unlimited capture, press `Ctrl+C`. NetSentinel prints a summary and
flushes reports when the capture ends. A BPF filter can reduce noise:

```powershell
python main.py --interface "Ethernet" --duration 120 --bpf "host 192.168.56.20" --report
```

Use the exact interface name and filter syntax supported by the installed
capture provider. If Windows reports no usable capture provider, install or
repair Npcap and restart the terminal with administrator privileges.

## Five safe live verification tests

Run these only between the two lab VMs, with the sensor listening on the
correct interface. Start NetSentinel before each test and use a short,
bounded duration. The exact alert name/severity can vary with configuration.

### Test 1: ICMP rate test (ping)

From the generator VM1, send more than the default 50 echo requests within
30 seconds to the sensor or another lab target:

```bash
ping -c 60 -i 0.1 192.168.56.10
```

On Windows, use a bounded loop from PowerShell:

```powershell
1..60 | ForEach-Object { ping.exe -n 1 -w 100 192.168.56.10 | Out-Null; Start-Sleep -Milliseconds 100 }
```

Expected result: `ICMP-001` should be eligible to alert when the requests are
observed from one source and the rule is enabled.

### Test 2: TCP port-diversity test (Nmap)

On the generator(Linux) VM, scan only the other lab VM:

```bash
nmap -Pn -T2 -p 1-30 192.168.56.10
```

This produces TCP SYN traffic to more than the default 20 destination ports.
Expected result: `TCP-001` may alert. Keep the scan range small and never run
this command against an Internet address or an unapproved network.

### Test 3: UDP port-diversity test

Use Nmap's bounded UDP scan against the target(in linux --> Ubuntu):

```bash
nmap -sU -Pn -T2 -p 1000-1016 192.168.56.10
```

Expected result: `UDP-001` may alert after the source reaches the configured
distinct-port threshold. UDP scans are slower; allow enough capture time.

### Test 4: DNS anomaly test using a script

Run this only when the lab has a DNS resolver you control. The script sends
bounded queries for deliberately nonexistent names and should not be pointed
at a public resolver without permission:

```python
from scapy.all import IP, UDP, DNS, DNSQR, send

target = "192.168.56.10"  # controlled lab DNS target
packets = [
    IP(dst=target) / UDP(sport=40000 + i, dport=53)
    / DNS(rd=1, qd=DNSQR(qname=f"netsentinel-test-{i}.invalid"))
    for i in range(25)
]
send(packets, verbose=False)
```

The default `DNS-002` NXDOMAIN threshold is 20 responses. Whether responses
are visible depends on the resolver and network path; if only requests are
captured, this test is useful for traffic visibility but may not trigger
`DNS-002`.

### Test 5: Controlled failed-login telemetry (brute-force simulation)

NetSentinel's current default rules do **not** implement a dedicated
username/password brute-force detector. You can still use a deliberately
configured lab SSH/HTTP service to verify that repeated connection attempts
are captured and logged, but keep the test small:

1. Create a disposable service and test account on VM 2.
2. Make five to ten intentionally invalid login attempts from VM 1.
3. Stop the test immediately and inspect the runtime log and reports.
4. Correlate the packet timestamps with the service's authentication log.

Do not use password-cracking tools or large credential lists. A real
brute-force detector would require application/authentication-log integration,
which is outside the current packet-only detection rules.

## Live test alternatives without two VMs

Two VMs are recommended because they provide a clean source and target, but
they are not mandatory:

- **One VM plus the host:** run NetSentinel in the VM and generate a small,
  authorized test traffic stream from the host over a host-only adapter.
- **One machine with a local service:** monitor traffic to a local web/DNS/SSH
  service. Prefer a real network adapter rather than loopback because some
  capture providers do not expose loopback traffic in the same way.
- **Offline synthetic traffic:** use `make_test_pcap.py` and
  `python main.py --offline data\test_traffic.pcap --report`. This is the most
  repeatable option and requires no second machine.
- **Replay a captured lab PCAP:** capture once in an isolated lab, then use
  offline analysis for repeatable tests and demonstrations.

# 4. Troubleshooting

### No interfaces are listed

Check Npcap/libpcap installation, run the terminal with the required
privileges, and confirm that the selected adapter is connected. On Linux,
check `ip link`; on Windows, check the adapter name returned by
`python main.py --list-interfaces`.

### No alerts are generated

Confirm that the selected interface is the lab interface, the traffic source
is actually reaching it, and the test exceeds the configured threshold.
Review the runtime log and `alerts/alerts.jsonl`. Also check that the relevant
rule's `"enabled"` value is `true` in `config.json`.

### Reports are not created

Use `--report`, confirm that the repository is writable, and check the
terminal error output. The `reports/` directory is created automatically.

### Baseline behavior is unexpected

Baseline learning is enabled by default for 300 seconds and is stored in
`data/baseline.json`. For a clean lab experiment, stop the sensor, remove or
back up that file, then start a new capture. Do not delete baseline data from
an environment where it is needed for ongoing monitoring without approval.

### Windows live capture fails or stops immediately

Confirm that Npcap is installed, that the selected interface is the adapter
connected to the lab network, and that the terminal has the required
privileges. Run `python main.py --list-interfaces` again after connecting the
adapter. If capture still fails, test the interface with a packet-capture
tool such as Wireshark and check the Npcap installation options.

### The dashboard is empty or missing historical sessions

The dashboard reads JSON reports from `reports/` and alert records from
`alerts/alerts.jsonl`; it does not parse arbitrary text logs. Generate at
least one report with `--report`, confirm those directories are readable, and
then run `python main.py --visualize` from the repository root.

### A test is visible but does not trigger an alert

Visibility and detection are different outcomes. Confirm that the traffic
matches the rule's protocol and source-based counting logic, that the
configured threshold is exceeded within the configured time window, and that
the rule is enabled. Deduplication and the alert suppression window can also
reduce repeated alerts. Inspect the JSON report for the rule counters instead
of relying only on terminal output.

# 5. Known Limitations and False-Positive Scenarios

NetSentinel is a focused, packet-based detector rather than a full enterprise
SIEM or endpoint detection platform. Important limitations include:

- It does not decrypt TLS, inspect encrypted application content, or identify
  the username behind an encrypted session.
- It does not currently provide a dedicated authentication brute-force rule.
  Authentication logs must be correlated separately with packet and runtime
  logs.
- It does not replace a firewall, antivirus product, vulnerability scanner,
  endpoint agent, or full packet-forensics platform.
- Detection depends on traffic visible on the selected interface. Switched
  networks, VLAN boundaries, Wi-Fi isolation, routing, NAT, tunnels, and
  container networking can hide relevant traffic.
- The default thresholds are demonstration values and may not fit a busy
  network. Baseline state is local to the configured data file and is not a
  distributed model.
- Alert history is append-oriented JSONL. It does not provide a central
  database, multi-user access control, retention policy, or automatic
  aggregation across sensors.
- Clock differences between hosts can make timestamp correlation less
  accurate. Use synchronized clocks when comparing sensor, service, and VM
  logs.

Common false-positive scenarios include:

- Legitimate vulnerability assessments, inventory tools, service discovery,
  backup systems, or monitoring agents can resemble TCP or UDP port scans.
- Operating-system health checks, monitoring, or a busy diagnostic tool can
  exceed the ICMP echo threshold.
- High-volume recursive DNS clients, software updates, test domains, or
  misconfigured applications can produce many queries or NXDOMAIN responses.
- ARP changes can be legitimate after DHCP reassignment, failover, VM
  migration, NIC replacement, or a load-balancer change.
- NAT, proxies, shared resolvers, and scanners behind one address can make
  unrelated activity appear to come from one source.

Treat an alert as a lead for investigation, not proof of compromise. Tune
thresholds, exclusions, trusted ARP mappings, and baseline data using known
normal traffic before using alerts for operational decisions.

# 6. Ethical and Authorized-Use Statement

NetSentinel must be used only for systems, networks, and packet captures that
you own or for which you have explicit, documented authorization. Before
starting a live capture or active test, define the approved scope, target
addresses, time window, traffic limits, data-retention rules, and a stop
procedure.

The example Nmap, ping, DNS, and failed-login exercises are for an isolated
lab or another explicitly authorized environment. Do not run them against
public IP addresses, third-party systems, shared corporate networks, or
production services without written approval. Do not collect credentials,
private communications, or unrelated users' traffic. Store captured data and
alerts securely, restrict access, and delete them according to the
organization's retention requirements.

The authors and contributors are not responsible for misuse, service
disruption, privacy violations, or unauthorized monitoring. If a test begins
to affect an out-of-scope system, stop it immediately and notify the
appropriate owner.

# 7. Future Improvements

Potential improvements, in priority order, include:

1. Add authentication and service-log ingestion for SSH, HTTP, DNS, and
   operating-system events, including a dedicated brute-force detector.
2. Add configurable alert actions such as email, webhook, desktop
   notification, and integration with a central event collector.
3. Add a central storage and retention layer with sensor identity,
   authentication, role-based access, and multi-sensor correlation.
4. Improve the dashboard with time-range filtering, session selection,
   exportable charts, drill-down alert details, and trend comparisons.
5. Add IPv6, richer protocol coverage, TLS metadata, DHCP, and additional
   network-behavior rules without storing sensitive payloads.
6. Improve threshold tuning with documented calibration workflows,
   per-network profiles, and more robust baseline anomaly models.
7. Add stronger operational packaging, service-mode deployment, log rotation,
   health checks, metrics, and alert delivery guarantees.
8. Expand automated tests with platform-specific capture checks and
   repeatable integration tests using isolated virtual networks.

## Development tests

Run the built-in test suite from the repository root:

```powershell
python -m unittest -q
```

The suite covers parsers, detection rules, alert management, baseline
handling, and report generation. Live capture tests should remain manual and
restricted to an authorized lab.
