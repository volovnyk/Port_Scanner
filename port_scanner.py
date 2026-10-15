#!/usr/bin/env python3
"""Concurrent TCP port scanner with service hints and report export."""

from __future__ import annotations

import argparse
import concurrent.futures
import errno
import json
import socket
import ssl
import sys
import time
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Sequence, Tuple


SERVICE_NAMES = {
    20: "ftp-data",
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "dns",
    80: "http",
    110: "pop3",
    143: "imap",
    443: "https",
    465: "smtps",
    587: "smtp",
    993: "imaps",
    995: "pop3s",
    3306: "mysql",
    5432: "postgresql",
}

UNREACHABLE_ERRNOS = {
    code
    for code in (
        getattr(errno, "EHOSTUNREACH", None),
        getattr(errno, "ENETUNREACH", None),
    )
    if code is not None
}


@dataclass
class OpenPort:
    port: int
    protocol: str
    service: str
    banner: Optional[str] = None


@dataclass
class PortProbe:
    result: Optional[OpenPort]
    reachable: bool
    unreachable: bool


def parse_ports(value: str) -> List[int]:
    """Parse comma-separated ports and inclusive ranges."""
    ports = set()
    for part in value.split(","):
        item = part.strip()
        if not item:
            raise argparse.ArgumentTypeError("port list contains an empty item")
        bounds = item.split("-")
        if len(bounds) == 1:
            start = end = bounds[0].strip()
        elif len(bounds) == 2:
            start, end = (bound.strip() for bound in bounds)
        else:
            raise argparse.ArgumentTypeError("use ports such as 22,80,443 or 1-1024")
        try:
            first = int(start)
            last = int(end)
        except ValueError as exc:
            raise argparse.ArgumentTypeError("ports must be integers") from exc
        if not (1 <= first <= 65535 and 1 <= last <= 65535):
            raise argparse.ArgumentTypeError("ports must be between 1 and 65535")
        if first > last:
            raise argparse.ArgumentTypeError("range start must not exceed range end")
        ports.update(range(first, last + 1))
    return sorted(ports)


def _clean_banner(data: bytes) -> Optional[str]:
    if not data:
        return None
    text = data.decode("utf-8", errors="replace")
    text = " ".join(text.replace("\x00", " ").split())
    return text[:240] or None


def _identify_service(
    connection: socket.socket, host: str, port: int
) -> Tuple[str, Optional[str]]:
    service = SERVICE_NAMES.get(port, "custom")
    banner = None

    try:
        connection.settimeout(0.35)
        if port == 80:
            request_host = host.replace("\r", "").replace("\n", "")
            connection.sendall(
                ("HEAD / HTTP/1.0\r\nHost: " + request_host +
                 "\r\nConnection: close\r\n\r\n").encode("ascii", errors="replace")
            )
            banner = _clean_banner(connection.recv(512))
        elif port == 5432:
            connection.sendall(b"\x00\x00\x00\x08\x04\xd2\x16\x2f")
            response = connection.recv(64)
            banner = "PostgreSQL SSL response: " + response[:1].decode(
                "ascii", errors="replace"
            ) if response else None
        elif port == 443:
            context = ssl.create_default_context()
            try:
                with context.wrap_socket(
                    connection, server_hostname=host
                ) as secure_connection:
                    secure_connection.settimeout(0.35)
                    secure_connection.sendall(
                        b"HEAD / HTTP/1.0\r\nConnection: close\r\n\r\n"
                    )
                    banner = _clean_banner(secure_connection.recv(512))
            except (OSError, ssl.SSLError):
                pass
        elif port in (465, 993, 995):
            return service, None
        else:
            banner = _clean_banner(connection.recv(512))
    except (OSError, ssl.SSLError):
        pass

    return service, banner


def _probe_port(
    host: str,
    port: int,
    family: int,
    address: Tuple[Any, ...],
    timeout: float,
) -> PortProbe:
    connection = socket.socket(family, socket.SOCK_STREAM)
    try:
        connection.settimeout(timeout)
        try:
            connection.connect(address)
        except socket.timeout:
            return PortProbe(None, reachable=False, unreachable=False)
        except OSError as exc:
            return PortProbe(
                None,
                reachable=exc.errno == errno.ECONNREFUSED,
                unreachable=exc.errno in UNREACHABLE_ERRNOS,
            )

        service, banner = _identify_service(connection, host, port)
        return PortProbe(
            OpenPort(port=port, protocol="tcp", service=service, banner=banner),
            reachable=True,
            unreachable=False,
        )
    finally:
        connection.close()


def scan_host(
    host: str,
    ports: Sequence[int],
    timeout: float = 0.75,
    workers: int = 100,
) -> Dict[str, Any]:
    """Scan TCP ports on a host and return a JSON-serializable report."""
    addresses = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    if not addresses:
        raise OSError("hostname did not resolve to an address")
    family, _, _, _, sockaddr = addresses[0]
    if family not in (socket.AF_INET, socket.AF_INET6):
        raise OSError("hostname resolved to an unsupported address family")

    started = datetime.now(timezone.utc)
    start_time = time.monotonic()
    open_ports: List[OpenPort] = []
    observed_reachable = False
    observed_unreachable = False

    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
        futures = []
        for port in ports:
            if family == socket.AF_INET:
                address = (sockaddr[0], port)
            else:
                address = (sockaddr[0], port, sockaddr[2], sockaddr[3])
            futures.append(
                executor.submit(
                    _probe_port, host, port, family, address, timeout
                )
            )
        for future in concurrent.futures.as_completed(futures):
            probe = future.result()
            if probe.result is not None:
                open_ports.append(probe.result)
            observed_reachable = observed_reachable or probe.reachable
            observed_unreachable = observed_unreachable or probe.unreachable

    open_ports.sort(key=lambda item: item.port)
    finished = datetime.now(timezone.utc)
    elapsed = time.monotonic() - start_time
    if observed_reachable:
        host_reachable: Optional[bool] = True
    elif observed_unreachable:
        host_reachable = False
    else:
        host_reachable = None

    return {
        "host": host,
        "ip_address": sockaddr[0],
        "started_at": started.isoformat(),
        "finished_at": finished.isoformat(),
        "elapsed_seconds": round(elapsed, 3),
        "ports_scanned": len(ports),
        "host_reachable": host_reachable,
        "open_ports": [asdict(item) for item in open_ports],
    }


def format_text_report(report: Dict[str, Any]) -> str:
    status = report["host_reachable"]
    reachability = (
        "reachable" if status is True else
        "unreachable" if status is False else
        "not confirmed"
    )
    lines = [
        "TCP Port Scan Report",
        "====================",
        "Host: {}".format(report["host"]),
        "IP address: {}".format(report["ip_address"]),
        "Host availability: {}".format(reachability),
        "Ports scanned: {}".format(report["ports_scanned"]),
        "Elapsed: {} seconds".format(report["elapsed_seconds"]),
        "",
        "Open ports:",
    ]
    open_ports = report["open_ports"]
    if not open_ports:
        lines.append("  None found")
    for item in open_ports:
        line = "  {}/{} - {}".format(
            item["port"], item["protocol"], item["service"]
        )
        if item["banner"]:
            line += " ({})".format(item["banner"])
        lines.append(line)
    return "\n".join(lines) + "\n"


def build_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Scan TCP ports and identify common services."
    )
    parser.add_argument("host", help="hostname or IP address to scan")
    parser.add_argument(
        "-p", "--ports",
        type=parse_ports,
        default=parse_ports("1-1024"),
        metavar="PORTS",
        help="comma-separated ports and ranges (default: 1-1024)",
    )
    parser.add_argument(
        "-t", "--timeout",
        type=float,
        default=0.75,
        help="connection timeout in seconds (default: 0.75)",
    )
    parser.add_argument(
        "-w", "--workers",
        type=int,
        default=100,
        help="maximum concurrent workers (default: 100)",
    )
    parser.add_argument(
        "--json", dest="json_path", metavar="FILE",
        help="write structured JSON results to FILE",
    )
    parser.add_argument(
        "--txt", dest="txt_path", metavar="FILE",
        help="write a human-readable text report to FILE",
    )
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_argument_parser()
    args = parser.parse_args(argv)
    if args.timeout <= 0:
        parser.error("--timeout must be greater than zero")
    if args.workers <= 0:
        parser.error("--workers must be greater than zero")

    try:
        report = scan_host(args.host, args.ports, args.timeout, args.workers)
        text_report = format_text_report(report)
        print(text_report, end="")
        if args.json_path:
            with open(args.json_path, "w", encoding="utf-8") as output:
                json.dump(report, output, indent=2)
                output.write("\n")
        if args.txt_path:
            with open(args.txt_path, "w", encoding="utf-8") as output:
                output.write(text_report)
    except (OSError, socket.gaierror) as exc:
        print("Scan failed: {}".format(exc), file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
