#!/usr/bin/env python3
import argparse
import ipaddress
import os
import platform
import socket
import ssl
import subprocess
import tempfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from datetime import datetime
from typing import List, Tuple


@dataclass
class ScanResult:
    ip: str
    port_open: bool
    tls_ok: bool
    common_name: str
    san_names: List[str]
    dns_match_status: str
    note: str


@dataclass
class LocalInterface:
    name: str
    ipv4_addresses: List[str]


def detect_local_ipv4() -> str:
    probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        probe.connect(("8.8.8.8", 80))
        local_ip = probe.getsockname()[0]
    finally:
        probe.close()
    return local_ip


def list_interface_ipv4_addresses(iface_name: str) -> List[str]:
    system = platform.system().lower()
    addresses: List[str] = []

    try:
        if system == "darwin":
            output = subprocess.check_output(
                ["ipconfig", "getifaddr", iface_name],
                text=True,
                stderr=subprocess.DEVNULL,
            ).strip()
            if output:
                ipaddress.IPv4Address(output)
                addresses.append(output)
        elif system == "linux":
            output = subprocess.check_output(
                ["ip", "-4", "-o", "addr", "show", "dev", iface_name],
                text=True,
                stderr=subprocess.DEVNULL,
            )
            for line in output.splitlines():
                parts = line.split()
                if "inet" in parts:
                    inet_idx = parts.index("inet")
                    if inet_idx + 1 < len(parts):
                        addr = parts[inet_idx + 1].split("/", 1)[0]
                        ipaddress.IPv4Address(addr)
                        addresses.append(addr)
    except Exception:
        return []

    return sorted(set(addresses), key=lambda ip: tuple(map(int, ip.split("."))))


def list_local_interfaces() -> List[LocalInterface]:
    interfaces: List[LocalInterface] = []
    for _, name in socket.if_nameindex():
        interfaces.append(LocalInterface(name=name, ipv4_addresses=list_interface_ipv4_addresses(name)))
    interfaces.sort(key=lambda i: i.name)
    return interfaces


def resolve_scan_source_ip(
    selected_iface: str | None, interfaces: List[LocalInterface], parser: argparse.ArgumentParser
) -> Tuple[str, str]:
    if selected_iface:
        for iface in interfaces:
            if iface.name == selected_iface:
                if not iface.ipv4_addresses:
                    parser.error(f"Interface '{selected_iface}' has no IPv4 address")
                return iface.name, iface.ipv4_addresses[0]
        available = ", ".join(i.name for i in interfaces) or "none"
        parser.error(f"Unknown interface '{selected_iface}'. Available: {available}")

    local_ip = detect_local_ipv4()
    for iface in interfaces:
        if local_ip in iface.ipv4_addresses:
            return iface.name, local_ip
    return "auto", local_ip


def is_port_open(ip: str, port: int, timeout: float) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(timeout)
        return sock.connect_ex((ip, port)) == 0


def parse_cert_names(cert_dict: dict) -> Tuple[str, List[str]]:
    cn = ""
    san: List[str] = []

    subject = cert_dict.get("subject", ())
    for rdn in subject:
        for key, val in rdn:
            if key == "commonName":
                cn = val
                break
        if cn:
            break

    for entry in cert_dict.get("subjectAltName", ()):
        if len(entry) == 2 and entry[0] == "DNS":
            san.append(entry[1])

    san = sorted(set(san))
    return cn, san


def fetch_cert_sni_candidates(ip: str, timeout: float) -> Tuple[bool, str, List[str], str]:
    """
    Returns:
      tls_ok, common_name, san_names, note
    """
    try:
        pem = ssl.get_server_certificate((ip, 443), timeout=timeout)
        with tempfile.NamedTemporaryFile("w", delete=False, suffix=".pem") as f:
            cert_path = f.name
            f.write(pem)
        try:
            cert_dict = ssl._ssl._test_decode_cert(cert_path)  # type: ignore[attr-defined]
        finally:
            os.unlink(cert_path)
    except Exception as exc:
        return False, "", [], f"TLS error: {exc}"

    cn, san = parse_cert_names(cert_dict)
    if not cn and not san:
        return True, "", [], "TLS ok, names not found in cert"
    return True, cn, san, ""


def resolve_ipv4_set(domain: str) -> set[str]:
    try:
        infos = socket.getaddrinfo(domain, None, socket.AF_INET, socket.SOCK_STREAM)
    except Exception:
        return set()
    return {info[4][0] for info in infos}


def calc_dns_match_status(ip: str, common_name: str, san_names: List[str]) -> str:
    domains = []
    if common_name:
        domains.append(common_name)
    domains.extend(san_names)
    domains = sorted(set(domains))

    if not domains:
        return "-"

    checked = 0
    matched = 0
    for domain in domains:
        # Wildcard names are not directly resolvable as-is.
        if "*" in domain:
            continue
        checked += 1
        resolved_ips = resolve_ipv4_set(domain)
        if ip in resolved_ips:
            matched += 1

    if checked == 0:
        return "-"
    if matched == checked:
        return "yes"
    if matched > 0:
        return "partial"
    return "no"


def scan_host(ip: str, timeout: float) -> ScanResult:
    if not is_port_open(ip, 443, timeout):
        return ScanResult(
            ip=ip,
            port_open=False,
            tls_ok=False,
            common_name="",
            san_names=[],
            dns_match_status="-",
            note="closed",
        )

    tls_ok, cn, san, note = fetch_cert_sni_candidates(ip, timeout)
    dns_match_status = calc_dns_match_status(ip, cn, san) if tls_ok else "-"
    return ScanResult(
        ip=ip,
        port_open=True,
        tls_ok=tls_ok,
        common_name=cn,
        san_names=san,
        dns_match_status=dns_match_status,
        note=note,
    )


def render_markdown(
    network: str,
    local_ip: str,
    selected_interface: str,
    interfaces: List[LocalInterface],
    results: List[ScanResult],
) -> str:
    open_443 = [r for r in results if r.port_open]
    tls_ok = [r for r in open_443 if r.tls_ok]
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    lines = [
        "# SNI scan report",
        "",
        f"- Generated: {now}",
        f"- Selected interface: `{selected_interface}`",
        f"- Local IP: `{local_ip}`",
        f"- Network scanned: `{network}`",
        f"- Hosts checked: `{len(results)}`",
        f"- 443 open: `{len(open_443)}`",
        f"- TLS parsed: `{len(tls_ok)}`",
        "",
        "## Local interfaces",
        "",
        "| Interface | IPv4 addresses |",
        "|---|---|",
    ]

    for iface in interfaces:
        iface_name = iface.name
        if iface.name == selected_interface:
            iface_name = f"{iface_name} (selected)"
        addr_text = ", ".join(f"`{ip}`" for ip in iface.ipv4_addresses) if iface.ipv4_addresses else "-"
        lines.append(f"| `{iface_name}` | {addr_text} |")

    if not interfaces:
        lines.append("| - | no interfaces found |")

    lines.extend(
        [
            "",
            "## Hosts with 443/tcp open",
            "",
            f"Server IP: `{local_ip}`",
            "",
            "| IP | TLS | CN | SAN (possible SNI) | DNS -> IP match | Note |",
            "|---|---|---|---|---|---|",
        ]
    )

    for r in open_443:
        tls = "yes" if r.tls_ok else "no"
        cn = r.common_name or "-"
        san = ", ".join(r.san_names) if r.san_names else "-"
        dns_match = r.dns_match_status
        note = r.note or "-"
        lines.append(f"| `{r.ip}` | {tls} | `{cn}` | `{san}` | {dns_match} | {note} |")

    if not open_443:
        lines.append("| - | - | - | - | - | no hosts with 443 open |")

    lines.extend(
        [
            "",
            "## Notes",
            "",
            "- `SAN/CN` from certificate are practical candidates for SNI values.",
            "- `DNS -> IP match`: `yes` if all resolvable cert names point to scanned IP, `partial` if some, `no` if none.",
            "- By default script checks local `/24`, can be changed with `--mask`.",
            "- Use `--interface` to scan from a specific local interface.",
        ]
    )
    return "\n".join(lines) + "\n"


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Scan local /24 network for port 443 and collect TLS cert names (SNI candidates)."
    )
    parser.add_argument(
        "-o",
        "--output",
        default="sni_scan_report.md",
        help="Output Markdown file path (default: sni_scan_report.md)",
    )
    parser.add_argument(
        "-t",
        "--timeout",
        type=float,
        default=1.2,
        help="Connection/TLS timeout in seconds (default: 1.2)",
    )
    parser.add_argument(
        "-w",
        "--workers",
        type=int,
        default=64,
        help="Parallel workers (default: 64)",
    )
    parser.add_argument(
        "-m",
        "--mask",
        type=int,
        default=24,
        help="Network mask bits for local subnet scan (default: 24)",
    )
    parser.add_argument(
        "-i",
        "--interface",
        default=None,
        help="Local interface name (example: en0). If omitted, auto-detect from default route.",
    )
    args = parser.parse_args()
    if not (0 <= args.mask <= 32):
        parser.error("--mask must be in range 0..32")

    interfaces = list_local_interfaces()
    selected_interface, local_ip = resolve_scan_source_ip(args.interface, interfaces, parser)
    net = ipaddress.ip_network(f"{local_ip}/{args.mask}", strict=False)
    hosts = [str(h) for h in net.hosts() if str(h) != local_ip]

    results: List[ScanResult] = []
    with ThreadPoolExecutor(max_workers=max(1, args.workers)) as pool:
        fut_map = {pool.submit(scan_host, ip, args.timeout): ip for ip in hosts}
        for fut in as_completed(fut_map):
            results.append(fut.result())

    results.sort(key=lambda r: tuple(map(int, r.ip.split("."))))
    md = render_markdown(str(net), local_ip, selected_interface, interfaces, results)

    with open(args.output, "w", encoding="utf-8") as f:
        f.write(md)

    print(f"[OK] Report saved to: {args.output}")
    print(
        f"[INFO] Interface: {selected_interface}, Local IP: {local_ip}, scanned: {net}, checked hosts: {len(hosts)}"
    )


if __name__ == "__main__":
    main()
