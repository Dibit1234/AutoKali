# AutoKali
A test kali autoscanner combining multiple well known kali tools.

AutoKali is a **safe recon** runner that reads a target list (IPs/domains), creates **one folder per target**, and saves **one output file per module**, plus:
- `90_all_outputs.txt` (concatenation of all outputs)
- `91_important.txt` (high-signal summary only)

## What runs (default ON)
- DNS resolution (domains -> IPs)
- Nmap ports + versions (default: common ports via `-F`)
  - `--TopPorts N` for top-N ports
  - `--ScanAll` for full 1–65535 (`-p-`)
- WhatWeb fingerprinting
- TLS scan via `sslscan`
  - `41_tls_findings.txt` contains **only** expired certs + weak/legacy indicators
- Passive web checks (no brute forcing)
  - probe http/https, fetch `robots.txt`, `sitemap.xml`, `/.well-known/security.txt`
  - extract links + form actions from homepage
- WordPress detection **only** (evidence + manual command suggestion; not executed)

## Install
```bash
sudo apt update
sudo apt install -y nmap whatweb sslscan curl
