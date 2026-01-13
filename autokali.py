#!/usr/bin/env python3
# AutoKali — safe recon orchestrator (no brute forcing, no vuln scanners)

import argparse
import concurrent.futures as cf
import ipaddress
import os
import re
import socket
import subprocess
import sys
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from urllib.parse import urljoin


BANNER = r"""
    _         _        _  __      _ _
   / \  _   _| |_ ___ | |/ /__ _ | (_)
  / _ \| | | | __/ _ \| ' // _` || | |
 / ___ \ |_| | || (_) | . \ (_| || | |
/_/   \_\__,_|\__\___/|_|\_\__,_|/ |_|   AutoKali
"""


# ---------------------------- utils ----------------------------

def have_tool(name: str) -> bool:
    from shutil import which
    return which(name) is not None

def safe_name(s: str) -> str:
    return re.sub(r"[^a-zA-Z0-9._-]+", "_", s)[:160]

def normalize_target(line: str) -> Optional[str]:
    line = line.strip()
    if not line or line.startswith("#"):
        return None
    line = re.sub(r"^https?://", "", line, flags=re.I)
    line = line.split("/")[0].strip()
    return line or None

def is_ip(s: str) -> bool:
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False

def resolve_domain(domain: str) -> List[str]:
    ips = set()
    try:
        infos = socket.getaddrinfo(domain, None)
        for fam, *_rest, sockaddr in infos:
            if fam in (socket.AF_INET, socket.AF_INET6):
                ips.add(sockaddr[0])
    except Exception:
        pass
    return sorted(ips)

def read_text(p: Path) -> str:
    if not p.exists():
        return ""
    return p.read_text(encoding="utf-8", errors="ignore")

def now_utc() -> str:
    return datetime.now(timezone.utc).isoformat()


# ---------------------------- progress ----------------------------

def fmt_time(sec: float) -> str:
    sec = int(max(0, sec))
    h = sec // 3600
    m = (sec % 3600) // 60
    s = sec % 60
    if h:
        return f"{h:02d}:{m:02d}:{s:02d}"
    return f"{m:02d}:{s:02d}"

def make_bar(frac: float, width: int = 30) -> str:
    frac = max(0.0, min(1.0, frac))
    fill = int(frac * width)
    return "[" + ("#" * fill) + ("-" * (width - fill)) + "]"

class Progress:
    def __init__(self, total_steps: int, verbose: str = "med"):
        self.total_steps = max(1, total_steps)
        self.done_steps = 0
        self.t0 = time.time()
        self.lock = threading.Lock()
        self.verbose = verbose  # low/med/high
        self.avg_step_sec = 6.0

    def step_done(self, step_sec: float):
        with self.lock:
            self.done_steps += 1
            a = 0.15
            self.avg_step_sec = (1 - a) * self.avg_step_sec + a * max(0.1, step_sec)
        self.render(prefix="Overall", force=True)

    def eta_total(self) -> float:
        with self.lock:
            remaining = self.total_steps - self.done_steps
            return max(0.0, remaining * self.avg_step_sec)

    def render(self, prefix: str = "Overall", force: bool = False):
        if self.verbose == "low" and not force:
            return
        with self.lock:
            done = self.done_steps
            total = self.total_steps
        elapsed = time.time() - self.t0
        eta = self.eta_total()
        bar = make_bar(done / total, width=34)
        msg = f"\r{prefix:7} {bar} {done}/{total}  elapsed {fmt_time(elapsed)}  ETA {fmt_time(eta)}"
        sys.stdout.write(msg)
        sys.stdout.flush()

def run_cmd_with_progress(
    cmd: List[str],
    out_file: Path,
    timeout: int,
    label: str,
    prog: Progress,
    est_sec: float,
    verbose: str,
) -> Tuple[int, str, float]:
    out_file.parent.mkdir(parents=True, exist_ok=True)
    t0 = time.time()

    if verbose == "high":
        print(f"\n[cmd] {label}: {' '.join(cmd)}")
    elif verbose == "med":
        print(f"\n[*] {label}")

    with out_file.open("wb") as f:
        try:
            p = subprocess.Popen(cmd, stdout=f, stderr=subprocess.STDOUT, env=os.environ.copy())
            start = time.time()
            last_draw = 0.0

            while True:
                rc = p.poll()
                elapsed = time.time() - start
                if rc is not None:
                    break

                if time.time() - last_draw >= 0.1:
                    frac = min(0.95, elapsed / max(1.0, est_sec))
                    bar = make_bar(frac, width=28)
                    eta = max(0.0, est_sec - elapsed)
                    sys.stdout.write(f"\r    {label:22} {bar}  ETA {fmt_time(eta)}")
                    sys.stdout.flush()
                    last_draw = time.time()

                if elapsed > timeout:
                    try:
                        p.terminate()
                        time.sleep(1)
                        if p.poll() is None:
                            p.kill()
                    except Exception:
                        pass
                    f.write(b"\n[!] TIMEOUT\n")
                    sys.stdout.write(f"\r    {label:22} {make_bar(1.0,28)}  TIMEOUT          \n")
                    sys.stdout.flush()
                    return 124, "timeout", time.time() - t0

                time.sleep(0.05)

            sys.stdout.write(f"\r    {label:22} {make_bar(1.0,28)}  done            \n")
            sys.stdout.flush()

            elapsed_total = time.time() - t0
            status = "ok" if rc == 0 else f"rc={rc}"
            return rc, status, elapsed_total

        except Exception as e:
            f.write(f"\n[!] ERROR: {e}\n".encode())
            sys.stdout.write(f"\r    {label:22} {make_bar(1.0,28)}  error           \n")
            sys.stdout.flush()
            return 1, "error", time.time() - t0


# ---------------------------- core data ----------------------------

@dataclass
class Target:
    raw: str
    kind: str
    ips: List[str]


# ---------------------------- modules ----------------------------

def mod_dns(t: Target, tdir: Path) -> None:
    out = tdir / "00_dns.txt"
    if t.kind == "domain":
        ips = resolve_domain(t.raw)
        out.write_text(
            f"domain: {t.raw}\nresolved_ips: {', '.join(ips) if ips else '(none)'}\n",
            encoding="utf-8",
        )
    else:
        out.write_text(f"ip: {t.raw}\n", encoding="utf-8")

def mod_nmap_ports_versions(
    t: Target, tdir: Path, scan_all: bool, top_ports: Optional[int], timing: str,
    prog: Progress, verbose: str
) -> None:
    if not have_tool("nmap"):
        (tdir / "10_nmap_missing.txt").write_text("nmap not found in PATH\n", encoding="utf-8")
        prog.step_done(0.2)
        return

    syn_ok = (os.geteuid() == 0)
    scan_flag = "-sS" if syn_ok else "-sT"

    if scan_all:
        port_args = ["-p-"]
        est = 150.0
        timeout = 7200
        label = "nmap all-ports"
    elif top_ports is not None:
        port_args = [f"--top-ports={top_ports}"]
        est = max(30.0, min(300.0, top_ports / 20.0))
        timeout = 3600
        label = f"nmap top-{top_ports}"
    else:
        port_args = ["-F"]
        est = 25.0
        timeout = 2400
        label = "nmap common"

    ips_to_scan = t.ips if t.ips else ([t.raw] if is_ip(t.raw) else [])
    if not ips_to_scan:
        (tdir / "10_nmap_skipped.txt").write_text("no IPs to scan\n", encoding="utf-8")
        prog.step_done(0.3)
        return

    for ip in ips_to_scan:
        out = tdir / f"10_nmap_{safe_name(ip)}.txt"
        cmd = ["nmap", scan_flag, *port_args, "-sV", "--version-light", timing, "--reason", "-Pn", ip]
        _, _, sec = run_cmd_with_progress(cmd, out, timeout=timeout, label=label, prog=prog, est_sec=est, verbose=verbose)
        prog.step_done(sec)

def mod_whatweb(t: Target, tdir: Path, prog: Progress, verbose: str) -> None:
    if not have_tool("whatweb"):
        (tdir / "30_whatweb_missing.txt").write_text("whatweb not found in PATH\n", encoding="utf-8")
        prog.step_done(0.2)
        return
    out = tdir / "30_whatweb.txt"
    probes = [f"http://{t.raw}", f"https://{t.raw}"]
    cmd = ["whatweb", "--no-errors", "--color=never"] + probes
    _, _, sec = run_cmd_with_progress(cmd, out, timeout=900, label="whatweb", prog=prog, est_sec=10.0, verbose=verbose)
    prog.step_done(sec)

WEAK_TOKENS = [
    "SSLv2", "SSLv3", "TLSv1.0", "TLSv1.1",
    "NULL", "EXP", "EXPORT",
    "RC4", "3DES", " DES ", "DES-CBC",
    "MD5", "SHA1",
    "aNULL", "eNULL", "anon",
]

def _try_parse_dt(s: str) -> Optional[datetime]:
    s = s.strip()
    s = re.sub(r"\b(GMT|UTC)\b", "", s, flags=re.I).strip()
    for fmt in ("%Y-%m-%d %H:%M:%S", "%b %d %H:%M:%S %Y", "%Y-%m-%d", "%d %b %Y %H:%M:%S"):
        try:
            return datetime.strptime(s, fmt).replace(tzinfo=timezone.utc)
        except Exception:
            continue
    return None

def parse_sslscan_findings(text: str) -> Tuple[bool, List[str], Optional[datetime], Optional[datetime]]:
    weak_lines: List[str] = []
    nb = None
    na = None
    for line in text.splitlines():
        l = line.strip()

        m = re.search(r"(Not valid before|Not Before)\s*:\s*(.+)$", l, re.I)
        if m and not nb:
            nb = _try_parse_dt(m.group(2).strip())

        m = re.search(r"(Not valid after|Not After)\s*:\s*(.+)$", l, re.I)
        if m and not na:
            na = _try_parse_dt(m.group(2).strip())

        if any(tok.lower() in l.lower() for tok in WEAK_TOKENS):
            if re.search(r"(Accepted|Preferred|TLS|SSL|Cipher|Signature|Protocol)", l, re.I):
                weak_lines.append(l)

    expired = bool(na and na < datetime.now(timezone.utc))
    weak_lines = list(dict.fromkeys(weak_lines))
    return expired, weak_lines, nb, na

def mod_tls_sslscan(t: Target, tdir: Path, prog: Progress, verbose: str) -> None:
    if not have_tool("sslscan"):
        (tdir / "40_sslscan_missing.txt").write_text("sslscan not found in PATH\n", encoding="utf-8")
        prog.step_done(0.2)
        return

    endpoints: List[str] = []
    if t.kind == "domain":
        endpoints.append(f"{t.raw}:443")
    if t.ips:
        endpoints.extend([f"{ip}:443" for ip in t.ips])
    elif is_ip(t.raw):
        endpoints.append(f"{t.raw}:443")

    if not endpoints:
        (tdir / "40_sslscan_skipped.txt").write_text("no TLS endpoints to scan\n", encoding="utf-8")
        prog.step_done(0.2)
        return

    raw_out = tdir / "40_sslscan_raw.txt"
    cmd = ["sslscan", "--no-colour", "--show-certificate"] + endpoints
    _, _, sec = run_cmd_with_progress(cmd, raw_out, timeout=1800, label="sslscan", prog=prog, est_sec=12.0, verbose=verbose)
    prog.step_done(sec)

    findings_out = tdir / "41_tls_findings.txt"
    raw_text = read_text(raw_out)
    expired, weak_lines, nb, na = parse_sslscan_findings(raw_text)

    lines: List[str] = []
    if expired:
        lines.append("[EXPIRED CERTIFICATE]")
        if nb:
            lines.append(f"NotBefore (UTC): {nb.isoformat()}")
        if na:
            lines.append(f"NotAfter  (UTC): {na.isoformat()}")
        lines.append("")
    if weak_lines:
        lines.append("[WEAK/LEGACY INDICATORS]")
        lines.extend(weak_lines)
        lines.append("")

    findings_out.write_text(
        ("No expired certs or obvious weak/legacy indicators found.\n" if not lines else "\n".join(lines) + "\n"),
        encoding="utf-8",
    )

def http_fetch(url: str, timeout_s: int = 10, max_kb: int = 512) -> Tuple[int, Dict[str, str], str]:
    if not have_tool("curl"):
        return 0, {}, ""
    cmd = ["curl", "-k", "-sS", "-L", "--max-time", str(timeout_s), "-D", "-", url]
    try:
        p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, check=False)
        out = p.stdout.decode("utf-8", errors="ignore")
    except Exception:
        return 0, {}, ""

    parts = out.split("\r\n\r\n")
    if len(parts) < 2:
        parts = out.split("\n\n")
    if len(parts) < 2:
        return 0, {}, ""

    body = parts[-1][: max_kb * 1024]
    header_blocks = parts[:-1]
    last_headers = ""
    for hb in reversed(header_blocks):
        if "HTTP/" in hb:
            last_headers = hb
            break
    if not last_headers:
        last_headers = header_blocks[-1]

    status = 0
    headers: Dict[str, str] = {}
    lines = [l.strip("\r") for l in last_headers.splitlines() if l.strip()]
    if lines:
        m = re.match(r"HTTP/\d(?:\.\d)?\s+(\d+)", lines[0])
        if m:
            status = int(m.group(1))
    for l in lines[1:]:
        if ":" in l:
            k, v = l.split(":", 1)
            headers[k.strip().lower()] = v.strip()
    return status, headers, body

def mod_web_passive(t: Target, tdir: Path, prog: Progress, verbose: str) -> Dict[str, str]:
    if not have_tool("curl"):
        (tdir / "50_web_probe.txt").write_text("curl not found in PATH\n", encoding="utf-8")
        prog.step_done(0.2)
        return {"base_url": "", "homepage_body": ""}

    out = tdir / "50_web_probe.txt"
    rows: List[str] = []
    candidates = [f"https://{t.raw}", f"http://{t.raw}"]
    chosen = ""
    body_chosen = ""

    for url in candidates:
        st, hdr, body = http_fetch(url, timeout_s=10, max_kb=512)
        rows.append(f"URL: {url}")
        rows.append(f"Status: {st}")
        for k in ("server", "x-powered-by", "content-type", "location"):
            if k in hdr:
                rows.append(f"{k}: {hdr[k]}")
        rows.append("")
        if st and not chosen:
            chosen = url
            body_chosen = body

    out.write_text("\n".join(rows) + "\n", encoding="utf-8")
    prog.step_done(1.0)

    if chosen:
        fetch_map = {
            "51_robots.txt": urljoin(chosen + "/", "robots.txt"),
            "52_sitemap.txt": urljoin(chosen + "/", "sitemap.xml"),
            "53_security_txt.txt": urljoin(chosen + "/", ".well-known/security.txt"),
        }
        for fname, url in fetch_map.items():
            st, _, body = http_fetch(url, timeout_s=10, max_kb=256)
            (tdir / fname).write_text(f"URL: {url}\nStatus: {st}\n\n{body}\n", encoding="utf-8")
            prog.step_done(0.6)

        links = sorted(set(re.findall(r'href=["\']([^"\']+)["\']', body_chosen, flags=re.I)))
        forms = sorted(set(re.findall(r'<form[^>]+action=["\']([^"\']+)["\']', body_chosen, flags=re.I)))
        (tdir / "54_homepage_extract.txt").write_text(
            f"Base: {chosen}\n\n[LINKS]\n" + "\n".join(links[:500]) +
            "\n\n[FORM_ACTIONS]\n" + "\n".join(forms[:200]) + "\n",
            encoding="utf-8"
        )
        prog.step_done(0.8)

    return {"base_url": chosen, "homepage_body": body_chosen}

def mod_wp_detect(t: Target, tdir: Path, base_url: str, homepage_body: str, prog: Progress) -> None:
    evidence: List[str] = []
    ww = read_text(tdir / "30_whatweb.txt")
    if re.search(r"\bWordPress\b", ww, flags=re.I):
        evidence.append("WhatWeb: WordPress fingerprint present")
    if homepage_body:
        if re.search(r"wp-content|wp-includes", homepage_body, flags=re.I):
            evidence.append("Homepage: wp-content/wp-includes references")
        if re.search(r'<meta[^>]+name=["\']generator["\'][^>]+wordpress', homepage_body, flags=re.I):
            evidence.append("Homepage: generator meta indicates WordPress")

    if base_url:
        for path in ("wp-login.php", "wp-json/"):
            st, _, _ = http_fetch(urljoin(base_url + "/", path), timeout_s=10, max_kb=32)
            if st in (200, 301, 302, 401, 403):
                evidence.append(f"Endpoint check: {path} returned {st}")

    out = tdir / "60_wp_detect.txt"
    if not evidence:
        out.write_text("No WordPress indicators detected.\n", encoding="utf-8")
        prog.step_done(0.3)
        return

    target_url = base_url if base_url else f"https://{t.raw}"
    out.write_text(
        "[WORDPRESS DETECTED]\n" +
        "\n".join(f"- {e}" for e in evidence) +
        "\n\n[MANUAL COMMAND]\n" +
        f"wpscan --url {target_url} --random-user-agent --format cli\n",
        encoding="utf-8",
    )
    prog.step_done(0.3)

def parse_nmap_open_ports(nmap_text: str) -> List[str]:
    out = []
    for l in nmap_text.splitlines():
        if re.match(r"^\d+/(tcp|udp)\s+open\s+", l):
            out.append(l.strip())
    return out

def write_all_outputs(tdir: Path) -> None:
    files = sorted([p for p in tdir.glob("*.txt") if p.name not in ("90_all_outputs.txt", "91_important.txt")])
    chunks = []
    for p in files:
        chunks.append(f"===== {p.name} =====")
        chunks.append(read_text(p).rstrip())
        chunks.append("")
    (tdir / "90_all_outputs.txt").write_text("\n".join(chunks).rstrip() + "\n", encoding="utf-8")

def write_important_outputs(t: Target, tdir: Path) -> None:
    imp = [f"Target: {t.raw}", f"RunUTC: {now_utc()}", ""]

    dns = read_text(tdir / "00_dns.txt").strip()
    if dns:
        imp += ["[DNS]", dns, ""]

    nmap_files = sorted(tdir.glob("10_nmap_*.txt"))
    open_lines: List[str] = []
    for nf in nmap_files:
        opens = parse_nmap_open_ports(read_text(nf))
        if opens:
            open_lines.append(f"{nf.name}:")
            open_lines.extend([f"  {x}" for x in opens])
    if open_lines:
        imp += ["[OPEN PORTS]"] + open_lines + [""]

    tls = read_text(tdir / "41_tls_findings.txt").strip()
    if tls and not tls.lower().startswith("no expired certs"):
        imp += ["[TLS FINDINGS]", tls, ""]

    probe = read_text(tdir / "50_web_probe.txt").strip()
    if probe:
        key = []
        for l in probe.splitlines():
            if l.startswith("URL:") or l.startswith("Status:") or l.lower().startswith(("server:", "x-powered-by:", "content-type:", "location:")):
                key.append(l)
        if key:
            imp += ["[WEB PROBE]"] + key[:60] + [""]

    wp = read_text(tdir / "60_wp_detect.txt").strip()
    if wp.startswith("[WORDPRESS DETECTED]"):
        imp += ["[WORDPRESS]"] + wp.splitlines()[:25] + [""]

    (tdir / "91_important.txt").write_text("\n".join(imp).rstrip() + "\n", encoding="utf-8")


# ---------------------------- orchestration ----------------------------

def build_targets(input_path: Path) -> List[Target]:
    targets: List[Target] = []
    seen = set()
    for line in input_path.read_text(encoding="utf-8", errors="ignore").splitlines():
        t = normalize_target(line)
        if not t or t in seen:
            continue
        seen.add(t)
        if is_ip(t):
            targets.append(Target(raw=t, kind="ip", ips=[t]))
        else:
            targets.append(Target(raw=t, kind="domain", ips=resolve_domain(t)))
    return targets

def process_target(t: Target, outdir: Path, scan_all: bool, top_ports: Optional[int], timing: str, prog: Progress, verbose: str) -> Tuple[str, str]:
    tdir = outdir / safe_name(t.raw)
    tdir.mkdir(parents=True, exist_ok=True)

    if verbose != "low":
        print(f"\n=== Target {t.raw} ===")

    mod_dns(t, tdir)
    prog.step_done(0.2)

    if t.kind == "domain" and not t.ips:
        (tdir / "10_nmap_skipped.txt").write_text("domain did not resolve; nmap skipped\n", encoding="utf-8")
        prog.step_done(0.3)
    else:
        mod_nmap_ports_versions(t, tdir, scan_all, top_ports, timing, prog, verbose)

    mod_whatweb(t, tdir, prog, verbose)
    mod_tls_sslscan(t, tdir, prog, verbose)
    web_ctx = mod_web_passive(t, tdir, prog, verbose)
    mod_wp_detect(t, tdir, web_ctx.get("base_url", ""), web_ctx.get("homepage_body", ""), prog)

    write_all_outputs(tdir)
    write_important_outputs(t, tdir)

    return (t.raw, "done")

def build_readme_text() -> str:
    # Build safely without triple quotes
    lines = [
        "# AutoKali",
        "",
        "Safe recon runner that creates **one folder per target** and **one output file per module**, plus:",
        "- `90_all_outputs.txt` (concatenation)",
        "- `91_important.txt` (high-signal summary)",
        "",
        "## What it runs (default ON)",
        "- DNS resolve (domains -> A/AAAA)",
        "- Nmap ports + versions (default: common ports via `-F`)",
        "  - `--TopPorts N` for top-N ports",
        "  - `--ScanAll` for 1–65535 (`-p-`)",
        "- WhatWeb fingerprinting",
        "- TLS scan via `sslscan`",
        "  - `41_tls_findings.txt` includes **only** expired certificates and weak/legacy indicators",
        "- Passive web checks (no brute force)",
        "  - probe http/https, fetch `robots.txt`, `sitemap.xml`, `/.well-known/security.txt`",
        "  - extract links + form actions from homepage",
        "- WordPress detection only (evidence + manual command suggestion)",
        "",
        "## Install",
        "```bash",
        "sudo apt update",
        "sudo apt install -y nmap whatweb sslscan curl",
        "```",
        "",
        "## Run",
        "```bash",
        "chmod +x autokali.py",
        "./autokali.py -i targets.txt -o recon_out --threads 4 --verbose med",
        "```",
        "",
        "## Notes",
        "- This tool is intentionally **non-intrusive**: no directory brute forcing and no automated vulnerability scanners.",
        "",
    ]
    return "\n".join(lines)

def main():
    ap = argparse.ArgumentParser(
        prog="autokali",
        description="AutoKali: safe recon orchestrator with per-target folders, progress bars, and summaries.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    ap.add_argument("-i", "--input", help="Targets file (IPs/domains, one per line).")
    ap.add_argument("-o", "--out", default="recon_out", help="Output directory.")
    ap.add_argument("--threads", type=int, default=4, help="Parallel targets.")
    ap.add_argument("--timing", default="-T3", choices=["-T2", "-T3", "-T4"], help="Nmap timing template.")
    ap.add_argument("--ScanAll", action="store_true", help="Nmap all TCP ports (1-65535).")
    ap.add_argument("--TopPorts", type=int, default=None, help="Nmap top N TCP ports (overrides default common ports).")
    ap.add_argument("--verbose", default="med", choices=["low", "med", "high"], help="Verbosity level.")
    ap.add_argument("--write-readme", action="store_true", help="Write README.md into the output directory.")

    # Show help if user typed nothing (your request)
    if len(sys.argv) == 1:
        print(BANNER.strip("\n"))
        ap.print_help()
        sys.exit(0)

    args = ap.parse_args()

    print(BANNER.strip("\n"))

    # Require -i only when actually running
    if not args.input:
        ap.print_help()
        sys.exit(2)

    input_path = Path(args.input).expanduser()
    outdir = Path(args.out).expanduser()
    outdir.mkdir(parents=True, exist_ok=True)

    targets = build_targets(input_path)
    if not targets:
        print("No valid targets found.")
        sys.exit(1)

    steps = 0
    for t in targets:
        nmap_steps = max(1, len(t.ips)) if (t.kind == "ip" or t.ips) else 1
        # dns + nmap_per_ip + whatweb + sslscan + probe + 3 fetch + extract + wp
        steps += 1 + nmap_steps + 1 + 1 + 1 + 3 + 1 + 1

    prog = Progress(total_steps=steps, verbose=args.verbose)

    (outdir / "_meta.txt").write_text(
        "AutoKali run metadata\n"
        f"run_utc: {now_utc()}\n"
        f"targets: {len(targets)}\n"
        f"ScanAll: {args.ScanAll}\n"
        f"TopPorts: {args.TopPorts}\n"
        f"threads: {args.threads}\n"
        f"nmap: {'yes' if have_tool('nmap') else 'no'}\n"
        f"whatweb: {'yes' if have_tool('whatweb') else 'no'}\n"
        f"sslscan: {'yes' if have_tool('sslscan') else 'no'}\n"
        f"curl: {'yes' if have_tool('curl') else 'no'}\n",
        encoding="utf-8"
    )

    if args.write_readme:
        (outdir / "README.md").write_text(build_readme_text(), encoding="utf-8")

    if args.verbose != "low":
        mode = "ALL ports" if args.ScanAll else (f"top-{args.TopPorts}" if args.TopPorts else "common ports (-F)")
        print(f"\nTargets: {len(targets)} | Nmap: {mode} | Threads: {args.threads}\n")

    with cf.ThreadPoolExecutor(max_workers=max(1, args.threads)) as ex:
        futs = [ex.submit(process_target, t, outdir, args.ScanAll, args.TopPorts, args.timing, prog, args.verbose) for t in targets]
        for f in cf.as_completed(futs):
            target, status = f.result()
            if args.verbose != "low":
                print(f"[+] {target}: {status}")

    prog.render(prefix="Overall", force=True)
    print("\nDone.")

if __name__ == "__main__":
    main()
