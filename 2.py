import sys
import asyncio
import ssl
import time
import argparse
from urllib.parse import urlparse
from contextlib import AsyncExitStack
from typing import List
import random
from aioquic.asyncio import connect
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.h3.connection import H3_ALPN, H3Connection
from aioquic.h3.events import HeadersReceived, DataReceived
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import ConnectionTerminated
from aioquic.tls import CipherSuite

try:
    import uvloop
    asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())
except ImportError:
    print("Warning: uvloop not installed. Install for better performance: pip install uvloop")

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
        self.conn_sem = asyncio.Semaphore(30)  # Lower for stability, prevents server closures

    def quic_event_received(self, event):
        if isinstance(event, ConnectionTerminated):
            for stream_id, resp in list(self.streams.items()):
                if not resp.done.done():
                    resp.done.set_exception(ConnectionClosedError(f"Connection terminated: {event.error_code}"))
                    try:
                        resp.done.exception()  # Suppress unretrieved exception logs
                    except ConnectionClosedError:
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
            elif isinstance(h3_event, DataReceived):
                if h3_event.stream_ended:
                    resp.done.set_result(True)
                    self.streams.pop(sid, None)

    async def send_request(self, headers: List[tuple], timeout: float = 15.0) -> Http3Response:
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
                    wait_connected=True
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
            raise RuntimeError("Không thể thiết lập bất kỳ kết nối nào!")

        print(f"✓ Đã tạo {len(self.pool)}/{self.initial_pool_size} kết nối thành công")
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
                    needed = min(10, self.initial_pool_size - current)
                    print(f"Pool low: {current}/{self.initial_pool_size}, creating {needed} more...")
                    coros = [self._create_single_conn() for _ in range(needed)]
                    new_conns = await asyncio.gather(*coros)
                    added = [p for p in new_conns if p is not None]
                    self.pool.extend(added)
                    print(f"Replenished {len(added)}, total now: {len(self.pool)}")
            await asyncio.sleep(0.1)

    async def _create_single_conn(self):
        try:
            cm = connect(
                self.host,
                self.port,
                configuration=self.config,
                create_protocol=Http3ClientProtocol,
                wait_connected=True
            )
            protocol = await asyncio.wait_for(
                self._stack.enter_async_context(cm),
                timeout=12.0
            )
            return protocol
        except Exception:
            return None

    async def get_connection(self) -> Http3ClientProtocol:
        async with self._lock:
            if not self.pool:
                raise RuntimeError("No connections available in pool")
            return random.choice(self.pool)

    async def remove_connection(self, protocol: Http3ClientProtocol):
        async with self._lock:
            if protocol in self.pool:
                self.pool.remove(protocol)
                try:
                    protocol.close()
                except:
                    pass
                print(f"Removed bad connection. Pool size: {len(self.pool)}")

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

async def worker(
    worker_id: int,
    pool: ConnectionPool,
    headers: List[tuple],
    duration: float,
    counter: AtomicCounter,
    stats: dict,
    semaphore: asyncio.Semaphore,
    interval: float
):
    end_time = time.perf_counter() + duration
    request_count = 0
    error_count = 0
    next_send = time.perf_counter()

    while next_send < end_time:
        async with semaphore:
            conn = None
            for _ in range(5):
                try:
                    conn = await pool.get_connection()
                    break
                except RuntimeError:
                    await asyncio.sleep(0.05)
            if not conn:
                error_count += 1
                next_send += interval
                continue

            try:
                start = time.perf_counter()
                resp = await conn.send_request(headers, timeout=15.0)
                latency = (time.perf_counter() - start) * 1000
                await counter.increment()
                request_count += 1
                if request_count % 10 == 0:
                    stats.setdefault('latencies', []).append(latency)
                if not (resp.headers and any(k == b':status' and v == b'200' for k, v in resp.headers)):
                    raise ValueError("Non-200")
            except ConnectionClosedError:
                # Don't count closures as errors; server-side limit
                pass
            except Exception:
                error_count += 1
                await pool.remove_connection(conn)
            finally:
                next_send += interval
                delay = next_send - time.perf_counter()
                if delay > 0:
                    await asyncio.sleep(delay + random.uniform(0, 0.01))  # Jitter for realism
                elif delay < -interval * 2:
                    next_send = time.perf_counter() + interval

    async with stats['_lock']:
        stats['total_requests'] = stats.get('total_requests', 0) + request_count
        stats['total_errors'] = stats.get('total_errors', 0) + error_count

def build_headers(host: str, path: str) -> List[tuple]:
    return [
        (b":method", b"GET"),
        (b":scheme", b"https"),
        (b":authority", host.encode()),
        (b":path", path.encode()),
        (b"user-agent", b"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"),
        (b"accept", b"text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8"),
        (b"sec-ch-ua", b'"Chromium";v="131", "Google Chrome";v="131"'),
        (b"sec-ch-ua-mobile", b"?0"),
        (b"sec-ch-ua-platform", b'"Windows"'),
        (b"accept-encoding", b"gzip, deflate, br, zstd"),
        (b"accept-language", b"en-US,en;q=0.9"),
        (b"cache-control", b"no-cache"),
    ]

async def main():
    parser = argparse.ArgumentParser(description="Maximized RPS HTTP/3 Load Tester")
    parser.add_argument("--url", required=True, help="Target URL (HTTPS only)")
    parser.add_argument("--rps", type=int, required=True, help="Target requests per second")
    parser.add_argument("--workers", type=int, default=500, help="Number of worker tasks")
    parser.add_argument("--connections", type=int, default=100, help="QUIC connections in pool")
    parser.add_argument("--duration", type=int, default=30, help="Test duration in seconds")
    parser.add_argument("--max-concurrency", type=int, default=2000, help="Max concurrent requests")
    args = parser.parse_args()

    parsed = urlparse(args.url)
    if parsed.scheme != "https":
        raise SystemExit("Error: Only HTTPS URLs are supported.")

    config = QuicConfiguration(
        is_client=True,
        alpn_protocols=H3_ALPN,
        verify_mode=ssl.CERT_REQUIRED,
        cipher_suites=[
            CipherSuite.AES_128_GCM_SHA256,
            CipherSuite.AES_256_GCM_SHA384,
            CipherSuite.CHACHA20_POLY1305_SHA256,
        ],
        max_data=100 * 1024 * 1024,
        max_stream_data=50 * 1024 * 1024,
        idle_timeout=60.0,
        max_datagram_frame_size=65535,
    )

    print(f"Starting load test for {args.duration}s at {args.rps} RPS...")
    print(f"Workers: {args.workers} | Connections: {args.connections} | Max concurrency: {args.max_concurrency}")

    async with ConnectionPool(
        host=parsed.hostname,
        port=parsed.port or 443,
        config=config,
        pool_size=args.connections
    ) as pool:
        headers = build_headers(parsed.hostname, parsed.path or "/")
        counter = AtomicCounter()
        stats = {'_lock': asyncio.Lock(), 'total_requests': 0, 'total_errors': 0}
        semaphore = asyncio.Semaphore(args.max_concurrency)
        per_worker_rps = args.rps / args.workers if args.workers else args.rps
        interval = 1.0 / per_worker_rps if per_worker_rps > 0 else 0.01

        start_time = time.perf_counter()
        tasks = [asyncio.create_task(worker(i, pool, headers, args.duration, counter, stats, semaphore, interval))
                 for i in range(args.workers)]

        async def monitor():
            last = 0
            last_t = start_time
            while any(not t.done() for t in tasks):
                await asyncio.sleep(2)
                curr = await counter.get_value()
                now = time.perf_counter()
                rps = (curr - last) / (now - last_t) if (now - last_t) > 0 else 0
                print(f"Progress: {curr} req | RPS: {rps:.1f} | Errors: {stats.get('total_errors',0)} | Pool: {len(pool.pool)}")
                last, last_t = curr, now

        monitor_task = asyncio.create_task(monitor())
        await asyncio.gather(*tasks)
        monitor_task.cancel()

        total_time = time.perf_counter() - start_time
        total_req = await counter.get_value()
        avg_rps = total_req / total_time if total_time else 0

        print("\n" + "="*60)
        print("LOAD TEST COMPLETE")
        print("="*60)
        print(f"Runtime: {total_time:.2f}s")
        print(f"Total requests: {total_req}")
        print(f"Average RPS: {avg_rps:.2f} (Target: {args.rps})")
        print(f"Effectiveness: {(avg_rps/args.rps*100):.1f}%")
        print(f"Total errors: {stats.get('total_errors', 0)}")
        if stats.get('latencies'):
            lats = stats['latencies']
            print(f"Latency (ms): Avg={sum(lats)/len(lats):.1f} | P95={sorted(lats)[int(0.95*len(lats))]:.1f}")

if __name__ == "__main__":
    asyncio.run(main())
