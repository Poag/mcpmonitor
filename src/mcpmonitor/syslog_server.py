"""Syslog receiver (UDP and TCP). Fails closed: it only starts when a sender allowlist is configured."""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import time
from collections import deque
from dataclasses import dataclass, field

from .faults import FaultService
from .syslog_parse import SyslogMessage, parse

log = logging.getLogger(__name__)

MAX_LINE = 8192
QUEUE_MAX = 20000


def parse_allow(spec: str) -> list[ipaddress._BaseNetwork]:
    nets = []
    for part in spec.split(","):
        part = part.strip()
        if part:
            nets.append(ipaddress.ip_network(part, strict=False))
    return nets


@dataclass
class Stats:
    received: int = 0
    rejected: int = 0
    rate_dropped: int = 0
    queue_dropped: int = 0
    last_error: str = ""
    per_source: dict[str, int] = field(default_factory=dict)


class _Bucket:
    def __init__(self, rate: float) -> None:
        self.rate, self.tokens, self.at = rate, rate, time.monotonic()

    def take(self) -> bool:
        now = time.monotonic()
        self.tokens = min(self.rate, self.tokens + (now - self.at) * self.rate)
        self.at = now
        if self.tokens >= 1:
            self.tokens -= 1
            return True
        return False


class SyslogReceiver:
    def __init__(
        self,
        service: FaultService,
        allow: list[ipaddress._BaseNetwork],
        *,
        port: int,
        host: str = "0.0.0.0",
        rate_per_sec: float = 200,
        flush_interval: float = 1.0,
        batch_max: int = 500,
    ) -> None:
        if not allow:
            raise ValueError("syslog receiver needs a non-empty sender allowlist")
        self.service, self.allow, self.port, self.host = service, allow, port, host
        self.rate, self.flush_interval, self.batch_max = rate_per_sec, flush_interval, batch_max
        self.stats = Stats()
        self._queue: deque[tuple[float, SyslogMessage]] = deque()
        self._buckets: dict[str, _Bucket] = {}
        self._tasks: list[asyncio.Task] = []
        self._servers: list[asyncio.AbstractServer] = []
        self._transport: asyncio.DatagramTransport | None = None
        self.udp_port = self.tcp_port = port

    # -- intake --------------------------------------------------------------------------------------

    def accept(self, raw: str, sender_ip: str) -> bool:
        try:
            ip = ipaddress.ip_address(sender_ip)
        except ValueError:
            self.stats.rejected += 1
            return False
        if not any(ip in net for net in self.allow):
            self.stats.rejected += 1
            return False
        bucket = self._buckets.setdefault(sender_ip, _Bucket(self.rate))
        if not bucket.take():
            self.stats.rate_dropped += 1
            return False
        if len(self._queue) >= QUEUE_MAX:
            self.stats.queue_dropped += 1
            return False
        self.stats.received += 1
        self.stats.per_source[sender_ip] = self.stats.per_source.get(sender_ip, 0) + 1
        self._queue.append((time.time(), parse(raw[:MAX_LINE], sender_ip)))
        return True

    async def flush(self) -> None:
        while self._queue:
            batch = [self._queue.popleft() for _ in range(min(self.batch_max, len(self._queue)))]
            try:
                await self.service.ingest(batch)
            except Exception as exc:
                self.stats.last_error = f"{type(exc).__name__}: {exc}"
                log.exception("failed to ingest %d syslog lines", len(batch))

    async def _flusher(self) -> None:
        while True:
            await asyncio.sleep(self.flush_interval)
            await self.flush()

    # -- sockets -------------------------------------------------------------------------------------

    async def start(self) -> None:
        loop = asyncio.get_running_loop()
        receiver = self

        class UDP(asyncio.DatagramProtocol):
            def datagram_received(self, data: bytes, addr: tuple) -> None:
                receiver.accept(data.decode("utf-8", errors="replace"), addr[0])

        transport, _ = await loop.create_datagram_endpoint(UDP, local_addr=(self.host, self.port))
        self._transport = transport  # type: ignore[assignment]
        self.udp_port = transport.get_extra_info("sockname")[1]

        server = await asyncio.start_server(
            self._tcp_client, self.host, self.udp_port if self.port == 0 else self.port, limit=MAX_LINE
        )
        self._servers.append(server)
        self.tcp_port = server.sockets[0].getsockname()[1]
        self._tasks.append(asyncio.create_task(self._flusher()))
        log.info("syslog receiver listening on udp/%s tcp/%s", self.udp_port, self.tcp_port)

    async def _tcp_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        peer = writer.get_extra_info("peername")
        ip = peer[0] if peer else ""
        try:
            while True:
                try:
                    line = await asyncio.wait_for(reader.readline(), timeout=300)
                except (TimeoutError, asyncio.LimitOverrunError, ValueError):
                    break
                if not line:
                    break
                text = line.decode("utf-8", errors="replace").strip()
                if text and not self.accept(text, ip):
                    if not any(ipaddress.ip_address(ip) in n for n in self.allow):
                        break  # not an allowed sender: drop the connection
        finally:
            writer.close()

    async def stop(self) -> None:
        for t in self._tasks:
            t.cancel()
        for s in self._servers:
            s.close()
        if self._transport:
            self._transport.close()
        await self.flush()
