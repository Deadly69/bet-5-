import sys
import asyncio
import ssl
import time
import argparse
import random
from urllib.parse import urlparse
from contextlib import AsyncExitStack
from typing import List

from aioquic.asyncio import connect
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.h3.connection import H3_ALPN, H3Connection
from aioquic.h3.events import HeadersReceived
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import ConnectionTerminated
from aioquic.tls import CipherSuite

try:
    import uvloop
    asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())
except ImportError:
    print("Warning: uvloop not installed → pip install uvloop for better performance")

# ------------------------------------------------------------
# Realistic Chrome header pool (Chrome 131 era)
# ------------------------------------------------------------
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Edg/131.0.0.0",
]

SEC_CH_UA_VARIANTS = [
    '"Google Chrome";v="131", "Chromium";v="131", "Not=A?Brand";v="24"',
    '"Chromium";v="131", "Google Chrome";v="131", "Not=A?Brand";v="24"',
    '"Not=A?Brand";v="24", "Chromium";v="131", "Google Chrome";v="131"',
]

ACCEPT_LANGUAGES = [
    "en-US,en;q=0.9",
    "en-GB,en;q=0.9,en-US;q=0.8",
    "en,en-US;q=0.9",
    "fr-FR,fr;q=0.9,en;q=0.8",
    "de-DE,de;q=0.9,en;q=0.8",
]

class Http3Response:
    __slots__ = ('headers', 'done')
    def __init__(self):
        self.headers = None
        self.done = asyncio.get_event_loop().create_future()

class ConnectionClosedError(ConnectionError):
    pass

class Http3ClientProtocol(QuicConnectionProtocol):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.h3 = H3Connection(self._quic)
        self.streams = {}
        # Conservative limit – very important for Cloudflare stability
        self.conn_sem = asyncio.Semaphore(15)

    def quic_event_received(self, event):
        if isinstance(event, ConnectionTerminated):
            for stream_id, resp in list(self.streams.items()):
                if not resp.done.done():
                    resp.done.set_exception(ConnectionClosedError("Connection terminated"))
                    try:
                        resp.done.exception()  # suppress unretrieved warning
                    except:
                        pass
            self.streams.clear()
            return

        for h3_event in self.h3.handle_event(event):
            sid = getattr(h3_event, "stream_id", None)
            if sid not in self.streams:
                continue
            resp = self.streams[sid]
            if isinstance(h3_event, HeadersReceived):
                resp.headers = h3_event.headers
                if h3_event.stream_ended:
                    resp.done.set_result(True)
                    self.streams.pop(sid, None)

    async def send_request(self, headers: List[tuple], timeout: float = 20.0):
        async with self.conn_sem:
            stream_id = self._quic.get_next_available_stream_id()
            resp = Http3Response()
            self.streams[stream_id] = resp
            self.h3.send_headers(stream_id, headers, end_stream=True)
            self.transmit()
            try:
                await asyncio.wait_for(resp.done, timeout=timeout)
                return resp
            except Exception:
                self.streams.pop(stream_id, None)
                raise

class ConnectionPool:
    def __init__(self, host: str, port: int, config: QuicConfiguration, pool_size: int):
        self.host = host
        self.port = port
        self.config = config
        self.initial_pool_size = pool_size
        self.pool: List[Http3ClientProtocol] = []
        self._lock = asyncio.Lock()
        self._stack = None
        self._running = True

    async def __aenter__(self):
        self._stack = AsyncExitStack()
        async def create_conn():
            try:
                cm = connect(
                    self.host,
                    self.port,
                    configuration=self.config,
                    create_protocol=Http3ClientProtocol,
                    wait_connected=True,
                )
                protocol = await asyncio.wait_for(
                    self._stack.enter_async_context(cm),
                    timeout=12.0
                )
                return protocol
            except Exception:
                return None

        coros = [create_conn() for _ in range(self.initial_pool_size)]
        results = await asyncio.gather(*coros)
        self.pool = [p for p in results if p is not None]

        if not self.pool:
            raise RuntimeError("Failed to establish any connections!")

        print(f"✓ Created {len(self.pool)}/{self.initial_pool_size} connections")
        self._maintainer_task = asyncio.create_task(self._maintainer())
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        self._running = False
        if self._maintainer_task:
            self._maintainer_task.cancel()
        if self._stack:
            await self._stack.aclose()

    async def _maintainer(self):
        while self._running:
            async with self._lock:
                current = len(self.pool)
                if current < self.initial_pool_size:
                    needed = min(15, self.initial_pool_size - current)
                    coros = [self._create_single() for _ in range(needed)]
                    new = await asyncio.gather(*coros)
                    added = [p for p in new if p is not None]
                    self.pool.extend(added)
            await asyncio.sleep(0.2)

    async def _create_single(self):
        try:
            cm = connect(
                self.host,
                self.port,
                configuration=self.config,
                create_protocol=Http3ClientProtocol,
                wait_connected=True,
            )
            return await asyncio.wait_for(
                self._stack.enter_async_context(cm),
                timeout=12.0
            )
        except Exception:
            return None

    async def get_connection(self) -> Http3ClientProtocol:
        async with self._lock:
            if not self.pool:
                raise RuntimeError("No connections in pool")
            return random.choice(self.pool)

    async def remove_connection(self, protocol: Http3ClientProtocol):
        async with self._lock:
            if protocol in self.pool:
                self.pool.remove(protocol)
                try:
                    protocol.close()
                except:
                    pass
                print(f"Removed bad connection → Pool size: {len(self.pool)}")

class AtomicCounter:
    def __init__(self):
        self._value = 0
        self._lock = asyncio.Lock()
    async def increment(self):
        async with self._lock:
            self._value += 1
    async def get_value(self):
        async with self._lock:
            return self._value

def build_headers(host: str, path: str) -> List[tuple]:
    ua = random.choice(USER_AGENTS)
    sec_ch_ua = random.choice(SEC_CH_UA_VARIANTS)
    lang = random.choice(ACCEPT_LANGUAGES)

    return [
        (b":method", b"GET"),
        (b":authority", host.encode()),
        (b":scheme", b"https"),
        (b":path", path.encode()),
        (b"user-agent", ua.encode()),
        (b"accept", b"text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8"),
        (b"accept-language", lang.encode()),
        (b"accept-encoding", b"gzip, deflate, br, zstd"),
        (b"sec-ch-ua", sec_ch_ua.encode()),
        (b"sec-ch-ua-mobile", b"?0"),
        (b"sec-ch-ua-platform", b'"Windows"'),
        (b"upgrade-insecure-requests", b"1"),
        (b"sec-fetch-site", b"none"),
        (b"sec-fetch-mode", b"navigate"),
        (b"sec-fetch-user", b"?1"),
        (b"sec-fetch-dest", b"document"),
        (b"priority", b"u=0, i"),
        (b"cache-control", b"no-cache"),
    ]

async def worker(pool, headers, duration, counter, stats, semaphore, interval):
    end_time = time.perf_counter() + duration
    requests = errors = 0
    next_send = time.perf_counter()

    while next_send < end_time:
        async with semaphore:
            conn = None
            for _ in range(6):
                try:
                    conn = await pool.get_connection()
                    break
                except RuntimeError:
                    await asyncio.sleep(0.05)
            if not conn:
                errors += 1
                next_send += interval
                continue

            try:
                start = time.perf_counter()
                resp = await conn.send_request(headers)
                latency = (time.perf_counter() - start) * 1000
                await counter.increment()
                requests += 1
                if requests % 10 == 0:
                    stats.setdefault('latencies', []).append(latency)

                # Treat non-200 as error only if not Cloudflare challenge (optional)
                status = next((v for k, v in resp.headers if k == b":status"), None)
                if status not in (b"200", b"301", b"302"):
                    raise ValueError(f"Status {status.decode()}")
            except ConnectionClosedError:
                pass  # normal server limit
            except Exception:
                errors += 1
                await pool.remove_connection(conn)
            finally:
                next_send += interval
                delay = next_send - time.perf_counter()
                if delay > 0:
                    await asyncio.sleep(delay + random.uniform(0.005, 0.02))
                elif delay < -interval * 2:
                    next_send = time.perf_counter() + interval

    async with stats['_lock']:
        stats['requests'] = stats.get('requests', 0) + requests
        stats['errors'] = stats.get('errors', 0) + errors

async def main():
    parser = argparse.ArgumentParser(description="Educational HTTP/3 Load Tester (Cloudflare-friendly)")
    parser.add_argument("--url", required=True, help="Target URL (https only)")
    parser.add_argument("--rps", type=int, required=True, help="Target requests per second")
    parser.add_argument("--workers", type=int, default=400, help="Worker tasks")
    parser.add_argument("--connections", type=int, default=200, help="QUIC connection pool size")
    parser.add_argument("--duration", type=int, default=60, help="Test duration (seconds)")
    parser.add_argument("--max-concurrency", type=int, default=1500, help="Max concurrent requests")
    args = parser.parse_args()

    parsed = urlparse(args.url)
    if parsed.scheme != "https":
        sys.exit("Only HTTPS URLs supported")

    config = QuicConfiguration(
        is_client=True,
        alpn_protocols=H3_ALPN,
        verify_mode=ssl.CERT_REQUIRED,
        cipher_suites=[
            CipherSuite.AES_128_GCM_SHA256,
            CipherSuite.AES_256_GCM_SHA384,
            CipherSuite.CHACHA20_POLY1305_SHA256,
        ],
        max_data=200 * 1024 * 1024,
        max_stream_data=100 * 1024 * 1024,
        idle_timeout=120.0,
    )

    print(f"Testing {args.url} → {args.rps} RPS for {args.duration}s")
    print(f"Workers: {args.workers} | Connections: {args.connections}")

    async with ConnectionPool(parsed.hostname, parsed.port or 443, config, args.connections) as pool:
        headers = build_headers(parsed.hostname, parsed.path or "/")
        counter = AtomicCounter()
        stats = {'_lock': asyncio.Lock(), 'requests': 0, 'errors': 0}
        semaphore = asyncio.Semaphore(args.max_concurrency)
        interval = 1.0 / (args.rps / args.workers)

        start = time.perf_counter()
        tasks = [asyncio.create_task(worker(pool, headers, args.duration, counter, stats, semaphore, interval))
                 for _ in range(args.workers)]

        async def monitor():
            last = 0
            last_t = start
            while any(not t.done() for t in tasks):
                await asyncio.sleep(3)
                curr = await counter.get_value()
                now = time.perf_counter()
                rps = (curr - last) / (now - last_t) if (now - last_t) > 0 else 0
                print(f"Requests: {curr} | RPS: {rps:.1f} | Errors: {stats.get('errors',0)} | Pool: {len(pool.pool)}")
                last, last_t = curr, now

        monitor_task = asyncio.create_task(monitor())
        await asyncio.gather(*tasks)
        monitor_task.cancel()

        total_time = time.perf_counter() - start
        total = await counter.get_value()
        print("\n" + "="*60)
        print("TEST COMPLETE")
        print(f"Total requests: {total}")
        print(f"Avg RPS: {total/total_time:.1f} (target {args.rps})")
        print(f"Errors: {stats.get('errors', 0)}")
        if stats.get('latencies'):
            lats = stats['latencies']
            print(f"Latency (ms): Avg {sum(lats)/len(lats):.1f} | P95 {sorted(lats)[int(0.95*len(lats))]:.1f}")

if __name__ == "__main__":
    asyncio.run(main())
