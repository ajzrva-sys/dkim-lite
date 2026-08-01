#!/usr/bin/env python3
"""Measure end-to-end DKIM signing through a milter socket.

The client reuses one milter connection per worker so the result measures message
processing rather than TCP setup.  It also rejects responses that do not add a
DKIM-Signature header, preventing a fail-open path from looking fast.
"""

import argparse
import concurrent.futures
import json
import math
import socket
import statistics
import struct
import time


ADD_HEADERS = 0x00000001
CHANGE_HEADERS = 0x00000010
NR_HEADER = 0x00000080
NR_CONNECT = 0x00001000
NR_HELO = 0x00002000
NR_MAIL = 0x00004000
NR_RECIPIENT = 0x00008000
NR_EOH = 0x00040000
NR_BODY = 0x00080000
OFFERED_PROTOCOL = (
    NR_HEADER | NR_CONNECT | NR_HELO | NR_MAIL | NR_RECIPIENT | NR_EOH | NR_BODY
)


def send_packet(sock, command, payload=b""):
    value = command + payload
    sock.sendall(struct.pack("!I", len(value)) + value)


def receive_packet(sock):
    size = receive_exact(sock, 4)
    length = struct.unpack("!I", size)[0]
    if length < 1 or length > 1024 * 1024:
        raise RuntimeError(f"invalid response packet length {length}")
    return receive_exact(sock, length)


def receive_exact(sock, size):
    chunks = []
    remaining = size
    while remaining:
        chunk = sock.recv(remaining)
        if not chunk:
            raise RuntimeError("milter closed the connection")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def expect_continue(sock, label):
    response = receive_packet(sock)
    if response != b"c":
        raise RuntimeError(f"{label}: expected continue, got {response[:32]!r}")


def header(sock, protocol, name, value):
    send_packet(sock, b"L", name + b"\0" + value + b"\0")
    if not protocol & NR_HEADER:
        expect_continue(sock, "header")


def has_dkim_header(response):
    if response[:1] == b"h":
        return response[1:].lower().startswith(b"dkim-signature\0")
    if response[:1] == b"i" and len(response) >= 6:
        return response[5:].lower().startswith(b"dkim-signature\0")
    return False


def negotiate(sock):
    options = struct.pack("!III", 6, ADD_HEADERS | CHANGE_HEADERS, OFFERED_PROTOCOL)
    send_packet(sock, b"O", options)
    response = receive_packet(sock)
    if response[:1] != b"O" or len(response) != 13:
        raise RuntimeError(f"bad negotiation response {response!r}")
    protocol = struct.unpack("!I", response[9:13])[0]

    connect = b"benchmark.local\0" + b"4" + struct.pack("!H", 2525) + b"127.0.0.1\0"
    send_packet(sock, b"C", connect)
    if not protocol & NR_CONNECT:
        expect_continue(sock, "connect")
    send_packet(sock, b"H", b"benchmark.local\0")
    if not protocol & NR_HELO:
        expect_continue(sock, "helo")
    return protocol


def sign_message(sock, protocol, body, message_number):
    send_packet(sock, b"D", b"M{auth_authen}\0benchmark\0{i}\0BENCH%08d\0" % message_number)
    start = time.perf_counter_ns()
    send_packet(sock, b"M", b"<alice@example.com>\0")
    if not protocol & NR_MAIL:
        expect_continue(sock, "mail")
    send_packet(sock, b"R", b"<bob@example.net>\0")
    if not protocol & NR_RECIPIENT:
        expect_continue(sock, "recipient")
    header(sock, protocol, b"From", b"Alice <alice@example.com>")
    header(sock, protocol, b"To", b"Bob <bob@example.net>")
    header(sock, protocol, b"Subject", b"DKIM signer benchmark")
    header(sock, protocol, b"Date", b"Thu, 30 Jul 2026 12:00:00 -0400")
    header(sock, protocol, b"Message-ID", b"<benchmark@example.com>")
    header(sock, protocol, b"MIME-Version", b"1.0")
    header(sock, protocol, b"Content-Type", b"text/plain; charset=utf-8")
    send_packet(sock, b"N")
    if not protocol & NR_EOH:
        expect_continue(sock, "end of headers")
    for offset in range(0, len(body), 64 * 1024):
        send_packet(sock, b"B", body[offset : offset + 64 * 1024])
        if not protocol & NR_BODY:
            expect_continue(sock, "body")
    send_packet(sock, b"E")
    saw_signature = False
    while True:
        response = receive_packet(sock)
        if has_dkim_header(response):
            saw_signature = True
        if response[:1] in (b"a", b"r", b"t", b"d"):
            if response[:1] != b"a":
                raise RuntimeError(f"message not accepted: {response[:32]!r}")
            break
    elapsed = time.perf_counter_ns() - start
    if not saw_signature:
        raise RuntimeError("message accepted without a DKIM-Signature action")
    return elapsed


def make_body(size):
    line = b"The quick brown fox jumps over the lazy dog for a DKIM benchmark.\r\n"
    repeats = max(1, math.ceil(size / len(line)))
    return (line * repeats)[:size]


def run_worker(host, port, body, count, worker_number, timeout):
    timings = []
    with socket.create_connection((host, port), timeout=timeout) as sock:
        sock.settimeout(timeout)
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        protocol = negotiate(sock)
        for index in range(count):
            timings.append(
                sign_message(sock, protocol, body, worker_number * 10_000_000 + index)
            )
        send_packet(sock, b"Q")
    return timings


def percentile(values, percentage):
    ordered = sorted(values)
    rank = max(0, math.ceil(percentage * len(ordered)) - 1)
    return ordered[rank]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", required=True, type=int)
    parser.add_argument("--size", required=True, type=int)
    parser.add_argument("--messages", required=True, type=int)
    parser.add_argument("--concurrency", default=1, type=int)
    parser.add_argument("--warmup", default=10, type=int)
    parser.add_argument("--timeout", default=60.0, type=float)
    parser.add_argument("--label", required=True)
    args = parser.parse_args()
    if args.messages < args.concurrency or args.concurrency < 1:
        parser.error("messages must be at least concurrency, and concurrency must be positive")

    body = make_body(args.size)
    for index in range(args.warmup):
        run_worker(args.host, args.port, body, 1, 900 + index, args.timeout)

    base, extra = divmod(args.messages, args.concurrency)
    counts = [base + (1 if index < extra else 0) for index in range(args.concurrency)]
    started = time.perf_counter_ns()
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.concurrency) as executor:
        futures = [
            executor.submit(run_worker, args.host, args.port, body, count, index, args.timeout)
            for index, count in enumerate(counts)
        ]
        timings = [item for future in futures for item in future.result()]
    wall_ns = time.perf_counter_ns() - started

    millis = [value / 1_000_000 for value in timings]
    result = {
        "label": args.label,
        "body_bytes": len(body),
        "messages": len(timings),
        "concurrency": args.concurrency,
        "wall_seconds": round(wall_ns / 1_000_000_000, 6),
        "messages_per_second": round(len(timings) * 1_000_000_000 / wall_ns, 2),
        "latency_ms_median": round(statistics.median(millis), 3),
        "latency_ms_p95": round(percentile(millis, 0.95), 3),
        "latency_ms_max": round(max(millis), 3),
    }
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
