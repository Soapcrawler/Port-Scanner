#!/usr/bin/env python3
import argparse
import concurrent.futures
import csv
import socket
import sys
from dataclasses import dataclass


@dataclass(frozen=True)
class ScanResult:
    port: int
    service: str
    banner: str


def parse_ports(spec: str) -> list[int]:
    ports: set[int] = set()
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            start_s, end_s = part.split("-", 1)
            start, end = int(start_s), int(end_s)
            if not (1 <= start <= end <= 65535):
                raise ValueError(f"invalid port range: {part}")
            ports.update(range(start, end + 1))
        else:
            port = int(part)
            if not (1 <= port <= 65535):
                raise ValueError(f"invalid port: {part}")
            ports.add(port)
    return sorted(ports)


def service_name(port: int) -> str:
    try:
        return socket.getservbyport(port, "tcp")
    except OSError:
        return "unknown"


def clean_banner(raw: bytes, max_len: int = 120) -> str:
    text = raw.decode("utf-8", errors="replace").strip()
    if not text:
        return ""
    first_line = text.splitlines()[0].strip()
    return first_line[:max_len]


def grab_banner(sock: socket.socket, host: str, banner_timeout: float) -> str:
    sock.settimeout(banner_timeout)

    # 1. Passive read for services that speak first (SSH, SMTP, FTP, etc.)
    try:
        data = sock.recv(1024)
        if data:
            return clean_banner(data)
    except (socket.timeout, OSError):
        pass

    # 2. Active fallback probe for services waiting on a client request (HTTP)
    try:
        probe = f"HEAD / HTTP/1.0\r\nHost: {host}\r\n\r\n".encode("ascii", errors="ignore")
        sock.sendall(probe)
        data = sock.recv(1024)
        if data:
            return clean_banner(data)
    except (socket.timeout, OSError):
        pass

    return ""


def scan_port(
    family: int, ip: str, host: str, port: int, timeout: float
) -> ScanResult | None:
    with socket.socket(family, socket.SOCK_STREAM) as sock:
        sock.settimeout(timeout)
        try:
            sock.connect((ip, port))
        except (socket.timeout, OSError):
            return None

        banner = grab_banner(sock, host, banner_timeout=min(timeout, 1.5))
        return ScanResult(port=port, service=service_name(port), banner=banner)


def run_scan(
    family: int,
    ip: str,
    host: str,
    ports: list[int],
    timeout: float,
    workers: int,
) -> list[ScanResult]:
    results: list[ScanResult] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        futures = [
            pool.submit(scan_port, family, ip, host, port, timeout) for port in ports
        ]
        for future in concurrent.futures.as_completed(futures):
            res = future.result()
            if res is not None:
                results.append(res)
    return sorted(results, key=lambda r: r.port)


def write_csv(path: str, host: str, ip: str, results: list[ScanResult]) -> None:
    with open(path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow(["host", "ip", "port", "protocol", "state", "service", "banner"])
        for r in results:
            writer.writerow([host, ip, r.port, "tcp", "open", r.service, r.banner])


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Threaded TCP port scanner with banner grabbing and CSV export"
    )
    parser.add_argument("target", help="Target hostname or IP")
    parser.add_argument(
        "-p", "--ports", default="1-1024", help="Ports (e.g. 22,80,443 or 1-65535)"
    )
    parser.add_argument(
        "-t", "--timeout", type=float, default=1.0, help="Connection timeout in seconds"
    )
    parser.add_argument(
        "-w", "--workers", type=int, default=100, help="Number of worker threads"
    )
    parser.add_argument(
        "-o", "--output", default="scan_results.csv", help="Output CSV file path"
    )
    args = parser.parse_args()

    try:
        ports = parse_ports(args.ports)
    except ValueError as err:
        print(f"error: {err}", file=sys.stderr)
        return 2

    try:
        info = socket.getaddrinfo(args.target, None, type=socket.SOCK_STREAM)[0]
        family, ip = info[0], info[4][0]
    except socket.gaierror as err:
        print(f"error: could not resolve {args.target}: {err}", file=sys.stderr)
        return 1

    try:
        results = run_scan(family, ip, args.target, ports, args.timeout, args.workers)
    except KeyboardInterrupt:
        return 130

    for r in results:
        print(f"{r.port}/tcp\topen\t{r.service}\t{r.banner}")

    if args.output:
        try:
            write_csv(args.output, args.target, ip, results)
        except OSError as err:
            print(f"error: failed to write {args.output}: {err}", file=sys.stderr)
            return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
