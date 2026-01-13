#!/usr/bin/env python3
# AutoKali — safe recon orchestrator (no brute forcing, no automated vuln scanners)

import argparse
import concurrent.futures as cf
import ipaddress
import os
import re
import signal
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

VERSION = "1.3"

# Keep the 3 blank lines at the end (requested)
BANNER = rf"""
    _         _        _  __      _ _
   / \  _   _| |_ ___ | |/ /__ _ | (_)
  / _ \| | | | __/ _ \| ' // _` || | |
 / ___ \ |_| | || (_) | . \ (_| || | |
/_/   \_\__,_|\__\___/|_|\_\__,_|/ |_|   AutoKali v{VERSION}
 
 
 
""".rstrip("\n")

# Global stop flag used for fast graceful exit
STOP = threading.Event()

# Centralized defaults (tunable via CLI)
DEFAULT_TIMEOUTS = {
    "whois": 45,
    "dig": 30,
    "nmap_common": 2400,
    "nmap_top": 3600,
    "nmap_all": 7200,
    "whatweb": 900,
    "sslscan": 1800,
    "http_probe": 10,
    "http_fetch": 10,
    "http_connect": 3,
}

CONFIG: Dict[str, object] = {
    "timeout_mult": 1.0,
    "http_timeout": DEFAULT_TIMEOUTS["http_fetch"],
    "http_probe_timeout": DEFAULT_TIMEOUTS["http_probe"],
    "http_connect_timeout": DEFAULT_TIMEOUTS["http_connect"],
    "max_redirs": 5,
    "use_pn": True,
    "tls_only_if_https_or_443": True,
}


def T(key: str) -> int:
    """Scaled module timeouts."""
    mult = float(CONFIG.get("timeout_mult", 1.0))
    base = DEFAULT_TIMEOUTS[key]
    return int(max(1, base * mult))


# ---------------------------- argparse (banner help) ----------------------------

class BannerArgumentParser(argparse.ArgumentParser):
    def print_help(self, file=None):
        if file is None:
            file = sys.stdout
        print(BANNER, file=file)
        super().print_help(file=file)


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

def write_text(p: Path, s: str) -> None:
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(s, encoding="utf-8", errors="ignore")

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
        self.verbose = verbose
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


# ---------------------------- subprocess runner (fast cancel) ----------------------------

def run_cmd_with_progress(
    cmd: List[str],
    out_file: Path,
    timeout: int,
    label: str,
    est_sec: float,
    verbose: str,
) -> Tuple[int, str, float]:
    """
    Runs a command writing stdout+stderr to a file.
    Shows estimate-based per-command bar.
    If Ctrl+C is pressed, terminates the subprocess and returns quickly.
    """
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
                if STOP.is_set():
                    try:
                        p.terminate()
                        time.sleep(0.2)
                        if p.poll() is None:
                            p.kill()
                    except Exception:
                        pass
                    f.write(b"\n[!] STOPPED BY USER\n")
                    sys.stdout.write(f"\r    {label:22} {make_bar(1.0,28)}  stopped         \n")
                    sys.stdout.flush()
                    return 130, "stopped", time.time() - t0

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
                        time.sleep(0.5)
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


def run_capture_with_stop(cmd: List[str], timeout: int) -> Tuple[int, str, str, float]:
    """
    Run command capturing combined stdout+stderr into memory (for filtering),
    with STOP support (kills subprocess quickly).
    """
    t0 = time.time()
    try:
        p = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            env=os.environ.copy(),
        )
        chunks: List[bytes] = []
        start = time.time()

        while True:
            if STOP.is_set():
                try:
                    p.terminate()
                    time.sleep(0.2)
                    if p.poll() is None:
                        p.kill()
                except Exception:
                    pass
                txt = b"".join(chunks).decode("utf-8", errors="ignore")
                return 130, "stopped", txt, time.time() - t0

            rc = p.poll()
            if rc is not None:
                try:
                    rest = p.stdout.read() if p.stdout else b""
                    if rest:
                        chunks.append(rest)
                except Exception:
                    pass
                txt = b"".join(chunks).decode("utf-8", errors="ignore")
                status = "ok" if rc == 0 else f"rc={rc}"
                return rc, status, txt, time.time() - t0

            try:
                if p.stdout:
                    data = p.stdout.read1(4096)
                    if data:
                        chunks.append(data)
            except Exception:
                pass

            if time.time() - start > timeout:
                try:
                    p.terminate()
                    time.sleep(0.5)
                    if p.poll() is None:
                        p.kill()
                except Exception:
                    pass
                txt = b"".join(chunks).decode("utf-8", errors="ignore")
                return 124, "timeout", txt, time.time() - t0

            time.sleep(0.05)

    except Exception as e:
        return 1, f"error: {e}", "", time.time() - t0


# ---------------------------- data ----------------------------

@dataclass
class Target:
    raw: str
    kind: str
    ips: List[str]


# ---------------------------- web helpers ----------------------------

def http_fetch(
    url: str,
    timeout_s: int = 10,
    connect_timeout: int = 3,
    max_kb: int = 512,
    max_redirs: int = 5,
) -> Tuple[int, Dict[str, str], str]:
    """
    curl fetch with fast failure:
      - connect timeout
      - max time
      - redirect cap
      - filesize cap
    """
    if not have_tool("curl"):
        return 0, {}, ""

    # Note: --max-filesize is bytes
    cmd = [
        "curl",
        "-k", "-sS", "-L",
        "--connect-timeout", str(connect_timeout),
        "--max-time", str(timeout_s),
        "--max-redirs", str(max_redirs),
        "--max-filesize", str(max_kb * 1024),
        "-D", "-",
        url,
    ]

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


# ---------------------------- TLS parsing (sslscan) ----------------------------

WEAK_TOKENS = [
    "SSLv2", "SSLv3", "TLSv1.0", "TLSv1.1",
    "NULL", "EXP", "EXPORT",
    "RC4", "3DES", " DES ", "DES-CBC",
    "MD5", "SHA1",
    "aNULL", "eNULL", "anon",
]

def _try_parse_dt(s: str) -> Optional[datetime]:
    s = re.sub(r"\b(GMT|UTC)\b", "", s.strip(), flags=re.I).strip()
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


# ---------------------------- Nmap filtering ----------------------------

def extract_nmap_open_port_lines(nmap_text: str) -> List[str]:
    lines = []
    for l in nmap_text.splitlines():
        l = l.strip()
        if re.match(r"^\d+/(tcp|udp)\s+open\s+", l):
            lines.append(re.sub(r"\s+", " ", l))
    return lines

def nmap_has_open_443(nmap_text: str) -> bool:
    for l in nmap_text.splitlines():
        if l.strip().startswith("443/tcp") and re.search(r"\sopen\s", " " + l + " ", flags=re.I):
            return True
    return False


# ---------------------------- modules ----------------------------

def mod_dns(t: Target, tdir: Path) -> None:
    out = tdir / "00_dns.txt"
    if t.kind == "domain":
        ips = resolve_domain(t.raw)
        write_text(out, f"domain: {t.raw}\nresolved_ips: {', '.join(ips) if ips else '(none)'}\n")
    else:
        write_text(out, f"ip: {t.raw}\n")

def mod_whois(t: Target, tdir: Path, verbose: str) -> None:
    out = tdir / "01_whois.txt"
    if not have_tool("whois"):
        write_text(out, "whois not found in PATH\n")
        return
    if STOP.is_set():
        write_text(out, "stopped\n")
        return
    run_cmd_with_progress(["whois", t.raw], out, timeout=T("whois"), label="whois", est_sec=5.0, verbose=verbose)

def mod_dig(t: Target, tdir: Path, verbose: str) -> None:
    out = tdir / "02_dig.txt"
    if t.kind != "domain":
        write_text(out, "dig skipped (target is an IP)\n")
        return
    if not have_tool("dig"):
        write_text(out, "dig not found in PATH\n")
        return
    if STOP.is_set():
        write_text(out, "stopped\n")
        return
    cmd = ["dig", "+noall", "+answer", t.raw, "A", "AAAA", "MX", "NS", "TXT"]
    run_cmd_with_progress(cmd, out, timeout=T("dig"), label="dig", est_sec=3.0, verbose=verbose)

def mod_nmap(t: Target, tdir: Path, scan_all: bool, top_ports: Optional[int], timing: str, verbose: str) -> None:
    """
    Writes ONE file: 10_nmap.txt
    Format:
      =======IP=======
      <open port lines only>
      [ERROR] <timeout/rc/stopped> (if encountered)
    No extra Nmap fluff.
    """
    out = tdir / "10_nmap.txt"
    if not have_tool("nmap"):
        write_text(out, "[ERROR] nmap not found in PATH\n")
        return

    syn_ok = (os.geteuid() == 0)
    scan_flag = "-sS" if syn_ok else "-sT"

    if scan_all:
        port_args = ["-p-"]
        timeout = T("nmap_all")
        label = "nmap all-ports"
    elif top_ports is not None:
        port_args = [f"--top-ports={top_ports}"]
        timeout = T("nmap_top")
        label = f"nmap top-{top_ports}"
    else:
        port_args = ["-F"]
        timeout = T("nmap_common")
        label = "nmap common"

    ips_to_scan = t.ips if t.ips else ([t.raw] if is_ip(t.raw) else [])
    if not ips_to_scan:
        write_text(out, "[ERROR] no IPs to scan\n")
        return

    chunks: List[str] = []
    use_pn = bool(CONFIG.get("use_pn", True))

    for ip in ips_to_scan:
        if STOP.is_set():
            chunks.append(f"======={ip}======")
            chunks.append("[ERROR] stopped")
            chunks.append("")
            continue

        if verbose == "med":
            print(f"\n[*] {label} ({ip})")
        elif verbose == "high":
            print(f"\n[cmd] {label} ({ip})")

        # Put -Pn early (requested) for speed/reliability in environments that block host discovery.
        cmd = ["nmap"]
        if use_pn:
            cmd.append("-Pn")
        cmd += [scan_flag, *port_args, "-sV", "--version-light", timing, "--reason", ip]

        rc, status, txt, _sec = run_capture_with_stop(cmd, timeout=timeout)

        chunks.append(f"======={ip}======")

        open_lines = extract_nmap_open_port_lines(txt)
        if status != "ok":
            chunks.append(f"[ERROR] {status}")

        if open_lines:
            chunks.extend(open_lines)
        else:
            if status == "ok":
                chunks.append("No open ports found.")
        chunks.append("")

    write_text(out, "\n".join(chunks).rstrip() + "\n")

def mod_whatweb(t: Target, tdir: Path, verbose: str, base_url: str) -> None:
    out = tdir / "30_whatweb.txt"
    if not have_tool("whatweb"):
        write_text(out, "whatweb not found in PATH\n")
        return
    if STOP.is_set():
        write_text(out, "stopped\n")
        return
    if not base_url:
        write_text(out, "whatweb skipped (no reachable base URL)\n")
        return

    # Use only the working base URL for speed (instead of probing both schemes every time)
    cmd = ["whatweb", "--no-errors", "--color=never", base_url]
    run_cmd_with_progress(cmd, out, timeout=T("whatweb"), label="whatweb", est_sec=10.0, verbose=verbose)

def mod_sslscan(t: Target, tdir: Path, verbose: str, should_run: bool) -> None:
    raw_out = tdir / "40_sslscan_raw.txt"
    findings_out = tdir / "41_tls_findings.txt"

    if not should_run:
        write_text(raw_out, "sslscan skipped (no HTTPS/443 evidence)\n")
        write_text(findings_out, "sslscan skipped (no HTTPS/443 evidence)\n")
        return

    if not have_tool("sslscan"):
        write_text(raw_out, "sslscan not found in PATH\n")
        write_text(findings_out, "sslscan not found in PATH\n")
        return
    if STOP.is_set():
        write_text(raw_out, "stopped\n")
        write_text(findings_out, "stopped\n")
        return

    endpoints: List[str] = []
    if t.kind == "domain":
        endpoints.append(f"{t.raw}:443")
    if t.ips:
        endpoints.extend([f"{ip}:443" for ip in t.ips])
    elif is_ip(t.raw):
        endpoints.append(f"{t.raw}:443")

    if not endpoints:
        write_text(raw_out, "no TLS endpoints to scan\n")
        write_text(findings_out, "no TLS endpoints to scan\n")
        return

    cmd = ["sslscan", "--no-colour", "--show-certificate"] + endpoints
    run_cmd_with_progress(cmd, raw_out, timeout=T("sslscan"), label="sslscan", est_sec=12.0, verbose=verbose)

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

    write_text(findings_out, "No expired certs or obvious weak/legacy indicators found.\n" if not lines else "\n".join(lines) + "\n")

def mod_web_passive(t: Target, tdir: Path) -> Dict[str, str]:
    probe_out = tdir / "50_web_probe.txt"
    if not have_tool("curl"):
        write_text(probe_out, "curl not found in PATH\n")
        return {"base_url": "", "homepage_body": ""}

    if STOP.is_set():
        write_text(probe_out, "stopped\n")
        return {"base_url": "", "homepage_body": ""}

    candidates = [f"https://{t.raw}", f"http://{t.raw}"]
    chosen = ""
    body_chosen = ""
    rows: List[str] = []

    for url in candidates:
        if STOP.is_set():
            break
        st, hdr, body = http_fetch(
            url,
            timeout_s=int(CONFIG.get("http_probe_timeout", T("http_probe"))),
            connect_timeout=int(CONFIG.get("http_connect_timeout", T("http_connect"))),
            max_kb=64,  # smaller for probe
            max_redirs=int(CONFIG.get("max_redirs", 5)),
        )
        rows.append(f"URL: {url}")
        rows.append(f"Status: {st}")
        for k in ("server", "x-powered-by", "content-type", "location"):
            if k in hdr:
                rows.append(f"{k}: {hdr[k]}")
        rows.append("")
        if st and not chosen:
            chosen = url
            body_chosen = body

    write_text(probe_out, "\n".join(rows).rstrip() + "\n")

    if chosen and not STOP.is_set():
        fetch_map = {
            "51_robots.txt": urljoin(chosen + "/", "robots.txt"),
            "52_sitemap.txt": urljoin(chosen + "/", "sitemap.xml"),
            "53_security_txt.txt": urljoin(chosen + "/", ".well-known/security.txt"),
        }
        for fname, url in fetch_map.items():
            if STOP.is_set():
                break
            st, _hdr, body = http_fetch(
                url,
                timeout_s=int(CONFIG.get("http_timeout", T("http_fetch"))),
                connect_timeout=int(CONFIG.get("http_connect_timeout", T("http_connect"))),
                max_kb=256,
                max_redirs=int(CONFIG.get("max_redirs", 5)),
            )
            write_text(tdir / fname, f"URL: {url}\nStatus: {st}\n\n{body}\n")

        if not STOP.is_set():
            links = sorted(set(re.findall(r'href=["\']([^"\']+)["\']', body_chosen, flags=re.I)))
            forms = sorted(set(re.findall(r'<form[^>]+action=["\']([^"\']+)["\']', body_chosen, flags=re.I)))
            write_text(
                tdir / "54_homepage_extract.txt",
                f"Base: {chosen}\n\n[LINKS]\n" + "\n".join(links[:500]) +
                "\n\n[FORM_ACTIONS]\n" + "\n".join(forms[:200]) + "\n"
            )

    return {"base_url": chosen, "homepage_body": body_chosen}

def mod_endpoint_checks(t: Target, tdir: Path, base_url: str, endpoint_file: Optional[Path]) -> None:
    out = tdir / "55_endpoint_checks.txt"
    if not endpoint_file:
        write_text(out, "endpoint checks skipped (no --endpoint-file provided)\n")
        return
    if not base_url:
        write_text(out, "endpoint checks skipped (no reachable base URL)\n")
        return
    if not endpoint_file.exists():
        write_text(out, f"[ERROR] endpoint file not found: {endpoint_file}\n")
        return
    if not have_tool("curl"):
        write_text(out, "curl not found in PATH\n")
        return
    if STOP.is_set():
        write_text(out, "stopped\n")
        return

    paths = []
    for line in endpoint_file.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if not line.startswith("/"):
            line = "/" + line
        paths.append(line)

    if not paths:
        write_text(out, "endpoint file was empty\n")
        return

    rows = [f"Base: {base_url}", f"EndpointFile: {endpoint_file}", ""]
    for p in paths:
        if STOP.is_set():
            rows.append("[STOPPED]")
            break
        url = urljoin(base_url + "/", p.lstrip("/"))
        st, _hdr, _body = http_fetch(
            url,
            timeout_s=int(CONFIG.get("http_probe_timeout", T("http_probe"))),
            connect_timeout=int(CONFIG.get("http_connect_timeout", T("http_connect"))),
            max_kb=16,
            max_redirs=int(CONFIG.get("max_redirs", 5)),
        )
        rows.append(f"{st:>3}  {p}  ({url})")

    write_text(out, "\n".join(rows).rstrip() + "\n")

def mod_wp_detect(t: Target, tdir: Path, base_url: str, homepage_body: str) -> None:
    out = tdir / "60_wp_detect.txt"
    evidence: List[str] = []

    ww = read_text(tdir / "30_whatweb.txt")
    if re.search(r"\bWordPress\b", ww, flags=re.I):
        evidence.append("WhatWeb: WordPress fingerprint present")
    if homepage_body:
        if re.search(r"wp-content|wp-includes", homepage_body, flags=re.I):
            evidence.append("Homepage: wp-content/wp-includes references")
        if re.search(r'<meta[^>]+name=["\']generator["\'][^>]+wordpress', homepage_body, flags=re.I):
            evidence.append("Homepage: generator meta indicates WordPress")

    if base_url and not STOP.is_set():
        for path in ("wp-login.php", "wp-json/"):
            st, _hdr, _body = http_fetch(
                urljoin(base_url + "/", path),
                timeout_s=int(CONFIG.get("http_probe_timeout", T("http_probe"))),
                connect_timeout=int(CONFIG.get("http_connect_timeout", T("http_connect"))),
                max_kb=16,
                max_redirs=int(CONFIG.get("max_redirs", 5)),
            )
            if st in (200, 301, 302, 401, 403):
                evidence.append(f"Endpoint check: {path} returned {st}")

    if not evidence:
        write_text(out, "No WordPress indicators detected.\n")
        return

    write_text(out, "[WORDPRESS DETECTED]\n" + "\n".join(f"- {e}" for e in evidence) + "\n")


# ---------------------------- aggregations ----------------------------

def write_all_outputs(tdir: Path) -> None:
    out = tdir / "90_all_outputs.txt"
    files = sorted([p for p in tdir.glob("*.txt") if p.name not in ("90_all_outputs.txt", "91_important.txt")])
    chunks: List[str] = []
    for p in files:
        chunks.append(f"===== {p.name} =====")
        chunks.append(read_text(p).rstrip())
        chunks.append("")
    write_text(out, "\n".join(chunks).rstrip() + "\n")

def write_important_outputs(t: Target, tdir: Path) -> None:
    imp: List[str] = [f"Target: {t.raw}", f"RunUTC: {now_utc()}", ""]

    dns = read_text(tdir / "00_dns.txt").strip()
    if dns:
        imp += ["[DNS]", dns, ""]

    nmap_txt = read_text(tdir / "10_nmap.txt")
    open_lines = [l for l in nmap_txt.splitlines() if re.match(r"^\d+/(tcp|udp)\s+open\s+", l)]
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

    ep = read_text(tdir / "55_endpoint_checks.txt").strip()
    if ep and not ep.lower().startswith("endpoint checks skipped"):
        imp += ["[ENDPOINT CHECKS]"] + ep.splitlines()[:80] + [""]

    wp = read_text(tdir / "60_wp_detect.txt").strip()
    if wp.startswith("[WORDPRESS DETECTED]"):
        imp += ["[WORDPRESS]"] + wp.splitlines()[:50] + [""]

    write_text(tdir / "91_important.txt", "\n".join(imp).rstrip() + "\n")


# ---------------------------- README ----------------------------

def build_readme_text() -> str:
    lines = [
        "# AutoKali",
        "",
        f"Version: **{VERSION}**",
        "",
        "AutoKali is a **safe recon** runner that creates **one folder per target** and writes **one output file per module**, plus:",
        "- `90_all_outputs.txt` (concatenation of all outputs)",
        "- `91_important.txt` (high-signal summary only)",
        "",
        "## Efficiency / speed-related behavior",
        "- Centralized timeouts (tunable with `--timeout-mult`, `--http-timeout`, `--http-connect-timeout`, `--max-redirs`).",
        "- Nmap uses `-Pn` by default (disable with `--no-pn`).",
        "- WhatWeb runs only when a reachable base URL is found.",
        "- TLS scan can be skipped unless there is HTTPS/443 evidence (disable with `--tls-always`).",
        "",
        "## What it runs (defaults ON if tool exists)",
        "- DNS resolve (domains -> A/AAAA)",
        "- WHOIS (if `whois` installed)",
        "- DIG DNS records (if `dig` installed)",
        "- Nmap ports + versions (default: common ports via `-F`)",
        "  - `--TopPorts N` for top-N ports",
        "  - `--ScanAll` for full 1–65535 (`-p-`)",
        "  - Output is consolidated into `10_nmap.txt` with `=======IP=======` sections and **only** open ports + errors.",
        "- Passive web checks via `curl` (if installed)",
        "  - probe http/https, fetch `robots.txt`, `sitemap.xml`, `/.well-known/security.txt`",
        "  - extract links + form actions from homepage",
        "- WhatWeb fingerprinting (if `whatweb` installed; only when base URL reachable)",
        "- TLS scan via `sslscan` (if installed; by default only when HTTPS/443 evidence exists)",
        "- WordPress detection only (no scanning)",
        "- Optional allowlist endpoint checks: `--endpoint-file endpoints.txt`",
        "",
        "## Install dependencies (Kali)",
        "```bash",
        "sudo apt update",
        "sudo apt install -y nmap whatweb sslscan curl dnsutils whois",
        "```",
        "",
        "## Run",
        "```bash",
        "chmod +x autokali.py",
        "./autokali.py -i targets.txt -o recon_out --threads 4 --verbose med",
        "```",
        "",
        "## Graceful exit",
        "- Press `Ctrl+C` once to stop quickly with no traceback.",
        "",
    ]
    return "\n".join(lines)


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

def process_target(
    t: Target,
    outdir: Path,
    scan_all: bool,
    top_ports: Optional[int],
    timing: str,
    verbose: str,
    endpoint_file: Optional[Path],
    prog: Progress,
) -> Tuple[str, str]:
    if STOP.is_set():
        return (t.raw, "stopped")

    tdir = outdir / safe_name(t.raw)
    tdir.mkdir(parents=True, exist_ok=True)

    if verbose != "low":
        print(f"\n=== Target {t.raw} ===")

    # coarse steps for ETA smoothness
    mod_dns(t, tdir); prog.step_done(0.4)
    mod_whois(t, tdir, verbose); prog.step_done(0.8)
    mod_dig(t, tdir, verbose); prog.step_done(0.8)

    mod_nmap(t, tdir, scan_all, top_ports, timing, verbose); prog.step_done(1.2)
    nmap_txt = read_text(tdir / "10_nmap.txt")

    web_ctx = mod_web_passive(t, tdir); prog.step_done(0.8)
    base_url = web_ctx.get("base_url", "")

    # WhatWeb only when there is something to fingerprint
    mod_whatweb(t, tdir, verbose, base_url=base_url); prog.step_done(0.8)

    # TLS scan only when there is evidence (by default)
    tls_should_run = True
    if bool(CONFIG.get("tls_only_if_https_or_443", True)):
        tls_should_run = bool(base_url.startswith("https://")) or nmap_has_open_443(nmap_txt)
    mod_sslscan(t, tdir, verbose, should_run=tls_should_run); prog.step_done(0.8)

    mod_endpoint_checks(t, tdir, base_url, endpoint_file); prog.step_done(0.6)
    mod_wp_detect(t, tdir, base_url, web_ctx.get("homepage_body", "")); prog.step_done(0.4)
    write_all_outputs(tdir); write_important_outputs(t, tdir); prog.step_done(0.6)

    return (t.raw, "done" if not STOP.is_set() else "stopped")


# ---------------------------- Ctrl+C handling ----------------------------

def _sigint_handler(signum, frame):
    # First Ctrl+C triggers STOP and returns immediately.
    if not STOP.is_set():
        STOP.set()
        print("\n[!] Ctrl+C received — stopping now...")
    else:
        # second Ctrl+C: immediate exit
        os._exit(130)


def main():
    signal.signal(signal.SIGINT, _sigint_handler)

    ap = BannerArgumentParser(
        prog="autokali",
        description="AutoKali: safe recon orchestrator with per-target folders, progress bars, and summaries.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    ap.add_argument("-i", "--input", help="Targets file (IPs/domains, one per line).")
    ap.add_argument("-o", "--out", default="recon_out", help="Output directory.")
    ap.add_argument("--threads", type=int, default=4, help="Parallel targets.")
    ap.add_argument("--timing", default="-T3", choices=["-T2", "-T3", "-T4"], help="Nmap timing template.")
    ap.add_argument("--ScanAll", action="store_true", help="Nmap all TCP ports (1-65535).")
    ap.add_argument("--TopPorts", type=int, default=None, help="Nmap top N TCP ports (overrides default common ports).")
    ap.add_argument("--verbose", default="med", choices=["low", "med", "high"], help="Verbosity level.")
    ap.add_argument("--write-readme", action="store_true", help="Write README.md into the output directory.")
    ap.add_argument("--endpoint-file", default=None, help="Optional file of explicit allowlist paths to check (one per line).")
    ap.add_argument("--version", action="version", version=f"AutoKali v{VERSION}")

    # Efficiency knobs
    ap.add_argument("--timeout-mult", type=float, default=1.0, help="Multiply module timeouts (e.g. 0.5 faster, 2.0 slower).")
    ap.add_argument("--http-timeout", type=int, default=DEFAULT_TIMEOUTS["http_fetch"], help="HTTP fetch max time (seconds).")
    ap.add_argument("--http-probe-timeout", type=int, default=DEFAULT_TIMEOUTS["http_probe"], help="HTTP probe max time (seconds).")
    ap.add_argument("--http-connect-timeout", type=int, default=DEFAULT_TIMEOUTS["http_connect"], help="HTTP connect timeout (seconds).")
    ap.add_argument("--max-redirs", type=int, default=5, help="Max HTTP redirects to follow.")
    ap.add_argument("--no-pn", action="store_true", help="Disable Nmap -Pn (host discovery enabled).")
    ap.add_argument("--tls-always", action="store_true", help="Always run sslscan (do not require HTTPS/443 evidence).")

    # no-args => banner+help
    if len(sys.argv) == 1:
        ap.print_help()
        sys.exit(0)

    args = ap.parse_args()

    # banner for normal runs
    print(BANNER)

    # Apply config
    CONFIG["timeout_mult"] = max(0.1, float(args.timeout_mult))
    CONFIG["http_timeout"] = max(1, int(args.http_timeout))
    CONFIG["http_probe_timeout"] = max(1, int(args.http_probe_timeout))
    CONFIG["http_connect_timeout"] = max(1, int(args.http_connect_timeout))
    CONFIG["max_redirs"] = max(0, int(args.max_redirs))
    CONFIG["use_pn"] = (not bool(args.no_pn))
    CONFIG["tls_only_if_https_or_443"] = (not bool(args.tls_always))

    if not args.input:
        ap.print_help()
        sys.exit(2)

    input_path = Path(args.input).expanduser().resolve()
    if not input_path.exists():
        print("\n[!] Input file not found.")
        print(f"    Provided: {args.input}")
        print(f"    Resolved: {input_path}")
        print(f"    CWD:      {Path.cwd()}")
        print("\n    Tip: run `ls -la` or pass an absolute path.")
        sys.exit(2)

    outdir = Path(args.out).expanduser().resolve()
    outdir.mkdir(parents=True, exist_ok=True)

    endpoint_file = Path(args.endpoint_file).expanduser().resolve() if args.endpoint_file else None

    targets = build_targets(input_path)
    if not targets:
        print("[!] No valid targets found.")
        sys.exit(1)

    # simple ETA model
    total_steps = max(1, 10 * len(targets))
    prog = Progress(total_steps=total_steps, verbose=args.verbose)

    (outdir / "_meta.txt").write_text(
        "AutoKali run metadata\n"
        f"version: {VERSION}\n"
        f"run_utc: {now_utc()}\n"
        f"targets: {len(targets)}\n"
        f"ScanAll: {args.ScanAll}\n"
        f"TopPorts: {args.TopPorts}\n"
        f"threads: {args.threads}\n"
        f"verbose: {args.verbose}\n"
        f"endpoint_file: {endpoint_file if endpoint_file else ''}\n"
        f"timeout_mult: {CONFIG['timeout_mult']}\n"
        f"http_timeout: {CONFIG['http_timeout']}\n"
        f"http_probe_timeout: {CONFIG['http_probe_timeout']}\n"
        f"http_connect_timeout: {CONFIG['http_connect_timeout']}\n"
        f"max_redirs: {CONFIG['max_redirs']}\n"
        f"use_pn: {CONFIG['use_pn']}\n"
        f"tls_only_if_https_or_443: {CONFIG['tls_only_if_https_or_443']}\n"
        f"nmap: {'yes' if have_tool('nmap') else 'no'}\n"
        f"whatweb: {'yes' if have_tool('whatweb') else 'no'}\n"
        f"sslscan: {'yes' if have_tool('sslscan') else 'no'}\n"
        f"curl: {'yes' if have_tool('curl') else 'no'}\n"
        f"dig: {'yes' if have_tool('dig') else 'no'}\n"
        f"whois: {'yes' if have_tool('whois') else 'no'}\n",
        encoding="utf-8"
    )

    if args.write_readme:
        (outdir / "README.md").write_text(build_readme_text(), encoding="utf-8")

    if args.verbose != "low":
        mode = "ALL ports" if args.ScanAll else (f"top-{args.TopPorts}" if args.TopPorts else "common ports (-F)")
        pn = "-Pn" if CONFIG["use_pn"] else "host-discovery"
        print(f"\nTargets: {len(targets)} | Nmap: {mode} | {pn} | Threads: {args.threads}\n")

    # Manual executor so we can shutdown(wait=False) for fast Ctrl+C exit
    ex = cf.ThreadPoolExecutor(max_workers=max(1, args.threads))
    futs: List[cf.Future] = []

    try:
        for t in targets:
            if STOP.is_set():
                break
            futs.append(ex.submit(
                process_target, t, outdir, args.ScanAll, args.TopPorts, args.timing, args.verbose, endpoint_file, prog
            ))

        # Poll completion without blocking forever so Ctrl+C is always responsive
        while futs and not STOP.is_set():
            done, not_done = cf.wait(futs, timeout=0.2, return_when=cf.FIRST_COMPLETED)
            for f in done:
                try:
                    target, status = f.result()
                    if args.verbose != "low":
                        print(f"[+] {target}: {status}")
                except Exception as e:
                    if not STOP.is_set():
                        print(f"[!] Error: {e}")
            futs = list(not_done)

    finally:
        # Cancel anything not started
        for f in futs:
            f.cancel()

        # Fast shutdown: don't wait for thread joins
        try:
            ex.shutdown(wait=False, cancel_futures=True)
        except TypeError:
            ex.shutdown(wait=False)

        if STOP.is_set():
            print("\n[!] AutoKali stopped by user.")
            sys.exit(130)

    prog.render(prefix="Overall", force=True)
    print("\n[+] AutoKali finished.")


if __name__ == "__main__":
    main()
