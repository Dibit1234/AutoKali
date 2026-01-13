# AutoKali

AutoKali is a **safe recon** runner that creates **one folder per target** and writes **one output file per module**, plus:
- `90_all_outputs.txt` (concatenation of all outputs)
- `91_important.txt` (high-signal summary only)

## What it runs (defaults ON)
### Network / Host
- DNS resolve (domains -> A/AAAA)
- WHOIS (if `whois` installed)
- DIG record dump (if `dig` installed)

### Port / Service Recon
- Nmap ports + versions (default: common ports via `-F`)
  - `--TopPorts N` for top-N ports
  - `--ScanAll` for full 1–65535 (`-p-`)
  - Output is consolidated into **one file**: `10_nmap.txt` with sections:
    ```
    =======<IP>=======
    <open port lines only>
    [ERROR] <timeout/rc>  (if encountered)
    ```

### Web (Passive)
- WhatWeb fingerprinting (if `whatweb` installed)
- TLS scan via `sslscan` (if installed)
  - `41_tls_findings.txt` contains **only**:
    - expired certificates
    - weak/legacy cipher/protocol indicators
- HTTP(S) probe + passive fetch via `curl` (if installed)
  - fetch: `robots.txt`, `sitemap.xml`, `/.well-known/security.txt`
  - extract homepage links + form actions (no brute forcing)

### Detection Only
- WordPress detection only (no scanning, no enumeration)

### Optional Allowlist Checks
- `--endpoint-file endpoints.txt`
  - checks **only the explicit paths you provide** (one per line)
  - writes `55_endpoint_checks.txt`

## Install dependencies (Kali)
```bash
sudo apt update
sudo apt install -y nmap whatweb sslscan curl dnsutils whois
