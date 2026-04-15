# ipscaner

Fast IP range scanner using raw ICMP sockets — no subprocess per host, live output.

## Download

- **Windows**: grab `ipscaner.exe` from [Releases](https://github.com/Isusami/ipscaner/releases) or [Actions](https://github.com/Isusami/ipscaner/actions)
- **macOS / Linux**: run `python3 ip_scanner.py` directly

## Usage

```
python3 ip_scanner.py           # interactive mode
python3 ip_scanner.py ip.txt    # load ranges from file
./ipscaner.exe                  # Windows (run as Administrator)
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

### Speed presets

| Preset   | Rate   | Reply wait | Best for                 |
| -------- | ------ | ---------- | ------------------------ |
| `fast`   | 5000/s | 1s         | Local / fast networks    |
| `normal` | 1000/s | 2s         | Internet (default)       |
| `slow`   | 200/s  | 3s         | Distant / lossy networks |

You can also enter a raw number (e.g. `2000`) for a custom rate.

## Cloudflare preset

Type `cf` at the prompt to instantly load 148 Cloudflare IP ranges (~1.7M IPs) merged from:

- `cloudflare.com/ips-v4` (official CDN ranges)
- `ipinfo.io/AS13335` (full ASN routing table)

No internet required — ranges are built into the binary.

## Output

Alive IPs are written to `output.txt` (or your chosen filename) **immediately** as each host responds — one IP per line. The file is safe to read during the scan and survives Ctrl+C with partial results.

```
1.1.1.1
1.1.1.2
104.16.0.5
...
```

## How it works

- Sends ICMP Echo Requests from a **single socket** at your chosen rate
- A receiver thread captures replies concurrently — no per-host subprocess overhead
- IPs are shuffled per subnet and **round-robin interleaved** across all ranges to avoid sequential scan patterns and ensure early hits across all subnets
- Duplicate IPs are filtered at both parse time and scan time

### Platform notes

| Platform | Socket type  | Root needed                |
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

Windows `.exe` is built automatically via GitHub Actions on every push.
