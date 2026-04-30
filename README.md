# ipscaner 

Fast IP range scanner — ICMP ping sweep or HTTP port-80 probe, live output.

## Download

Grab the latest binary from [Releases](https://github.com/Isusami/ipscaner/releases):

| Platform | File                                  |
| -------- | ------------------------------------- |
| Windows  | `ipscaner.exe` (run as Administrator) |
| Linux    | `ipscaner-linux-amd64`                |

macOS: run `python3 ip_scanner.py` directly (no root needed).

## Usage

```
python3 ip_scanner.py           # interactive mode
python3 ip_scanner.py ip.txt    # load ranges from file
./ipscaner.exe                  # Windows (run as Administrator)
sudo ./ipscaner-linux-amd64     # Linux
```

### Input modes

| Input         | Example                                                      |
| ------------- | ------------------------------------------------------------ |
| `cf`          | Load all Cloudflare IP ranges (built-in, no internet needed) |
| CIDR          | `192.168.1.0/24`                                             |
| Range         | `192.168.1 1 254`                                            |
| Dash notation | `1.2.3.1-50`                                                 |
| ASN / URL     | `https://ipinfo.io/AS13335`                                  |
| File          | `python3 ip_scanner.py ranges.txt`                           |

### Scan modes

| Mode   | How it works            | Root needed         | Best for                          |
| ------ | ----------------------- | ------------------- | --------------------------------- |
| `icmp` | Raw ICMP echo (default) | Yes (Linux/Windows) | Fast scans on permissive networks |
| `http` | TCP connect to port 80  | No                  | When ISP/firewall blocks ICMP     |

### Speed presets

| Preset   | ICMP rate | HTTP workers | Reply wait | Best for                 |
| -------- | --------- | ------------ | ---------- | ------------------------ |
| `fast`   | 5000/s    | 1000         | 1s         | Local / fast networks    |
| `normal` | 1000/s    | 500          | 1.5–2s     | Internet (default)       |
| `slow`   | 200/s     | 200          | 2–3s       | Distant / lossy networks |
| `auto`   | 200/s     | 300          | —          | Loops forever, appends   |

You can also enter a raw number (e.g. `2000`) for a custom rate / worker count.

## Cloudflare preset

Type `cf` at the prompt to instantly load **944 collapsed ranges (~1.58M IPs)** — no internet required, built into the binary.

## Auto scan

Choose `auto` as the speed to run the scan in a continuous loop:

- Uses slow settings to avoid rate-limiting
- Each pass reshuffles host order
- Results **appended** to the output file — never overwritten
- Each pass is timestamped in the file: `# --- scan #N  YYYY-MM-DD HH:MM:SS ---`
- Press Ctrl+C to stop at any time

## Output

Alive IPs are written to `output.txt` (or your chosen filename) **immediately** as each host responds — one IP per line. Safe to read during the scan.

```
1.1.1.1
1.0.0.1
104.16.0.5
...
```

## How it works

**ICMP mode:**

- Sends ICMP Echo Requests from a single socket at your chosen rate
- A receiver thread captures replies concurrently — no per-host subprocess overhead
- IPs are shuffled per subnet and round-robin interleaved across all ranges

**HTTP mode:**

- Opens a TCP connection to port 80 per host using a thread pool
- No raw socket required — works without root/admin
- Bypasses ISPs and firewalls that block ICMP
- A refused connection (RST) still counts as alive

### Platform notes

| Platform | ICMP socket  | Root needed                |
| -------- | ------------ | -------------------------- |
| macOS    | `SOCK_DGRAM` | No                         |
| Linux    | `SOCK_RAW`   | Yes (`sudo`)               |
| Windows  | `SOCK_RAW`   | Yes (Run as Administrator) |

If raw sockets are unavailable, falls back to subprocess `ping` automatically.

## Build from source

```bash
pip install pyinstaller
pyinstaller --onefile --name ipscaner ip_scanner.py
```

Windows/Linux binaries are built automatically via GitHub Actions on every push.
