"""Protocol checks; --release skips checks needing shortened build-time limits."""

import errno
import random
import select
import socket
import struct
import subprocess
import sys
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack
from pathlib import Path
from threading import Barrier


BINARY = Path(sys.argv.pop(1)).resolve()
FAULTS_ENABLED = "--faults" in sys.argv
if FAULTS_ENABLED:
    sys.argv.remove("--faults")
RELEASE_ENABLED = "--release" in sys.argv
if RELEASE_ENABLED:
    sys.argv.remove("--release")
requires_test_limits = unittest.skipIf(RELEASE_ENABLED, "requires shortened test limits")
GREETING = b"\x05\x01\x00"


def recv_exact(sock, length):
    data = bytearray()
    while len(data) < length:
        chunk = sock.recv(length - len(data))
        if not chunk:
            raise EOFError("connection closed")
        data.extend(chunk)
    return bytes(data)


def encode_address(host, port, domain=False):
    if domain:
        encoded = host.encode("ascii")
        address = b"\x03" + bytes([len(encoded)]) + encoded
    elif ":" in host:
        address = b"\x04" + socket.inet_pton(socket.AF_INET6, host)
    else:
        address = b"\x01" + socket.inet_aton(host)
    return address + struct.pack("!H", port)


def read_reply(sock):
    header = recv_exact(sock, 4)
    if header[3] == 1:
        host = socket.inet_ntop(socket.AF_INET, recv_exact(sock, 4))
    elif header[3] == 4:
        host = socket.inet_ntop(socket.AF_INET6, recv_exact(sock, 16))
    else:
        raise AssertionError(f"unexpected reply address type: {header[3]}")
    return header, (host, struct.unpack("!H", recv_exact(sock, 2))[0])


class ProxyTestCase(unittest.TestCase):
    listen_host = "127.0.0.1"
    proxy_arguments = ()

    def setUp(self):
        if ":" in self.listen_host:
            try:
                with socket.socket(socket.AF_INET6) as probe:
                    probe.bind((self.listen_host, 0))
            except OSError:
                self.skipTest("IPv6 loopback is unavailable")
        self.proxy = subprocess.Popen(
            [str(BINARY), *self.proxy_arguments, self.listen_host, "0"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
        )
        self.addCleanup(self.proxy.stderr.close)
        self.addCleanup(self.stop_proxy)
        with ThreadPoolExecutor(max_workers=1) as pool:
            try:
                line = pool.submit(self.proxy.stderr.readline).result(timeout=3)
                self.assertTrue(line.startswith("SOCKS5 listening on "), line)
                self.port = int(line.rsplit(":", 1)[1])
                self.assertGreater(self.port, 0)
                self.assertLessEqual(self.port, 65535)
                host = f"[{self.listen_host}]" if ":" in self.listen_host else self.listen_host
                self.assertEqual(line.strip(), f"SOCKS5 listening on {host}:{self.port}")
            except BaseException:
                # Unblock readline before joining the executor on startup failure.
                self.stop_proxy()
                raise

    def stop_proxy(self):
        if self.proxy.poll() is None:
            self.proxy.terminate()
        self.proxy.wait(timeout=3)

    def control(self):
        sock = socket.create_connection((self.listen_host, self.port), 2)
        self.addCleanup(sock.close)
        sock.settimeout(5)
        sock.sendall(GREETING)
        self.assertEqual(recv_exact(sock, 2), b"\x05\x00")
        return sock

    def associate(self, control, port=0):
        control.sendall(b"\x05\x03\x00" + encode_address("0.0.0.0", port))
        header, endpoint = read_reply(control)
        self.assertEqual(header[:3], b"\x05\x00\x00")
        return endpoint

    def assert_closed(self, sock):
        try:
            self.assertEqual(sock.recv(1), b"")
        except ConnectionError:
            pass

    def simultaneous_tcp_streams(self):
        # Different aperiodic streams expose loss, repetition and cross-direction mixing.
        upload_size, download_size = 1024 * 1024 + 137, 1024 * 1024 + 509
        upload = random.Random(21).getrandbits(upload_size * 8).to_bytes(upload_size, "little")
        download = random.Random(22).getrandbits(download_size * 8).to_bytes(download_size, "little")
        with ThreadPoolExecutor(max_workers=4) as pool, socket.socket() as listener, \
                self.control() as control:
            listener.bind(("127.0.0.1", 0))
            listener.listen()
            listener.settimeout(2)
            control.sendall(b"\x05\x01\x00" + encode_address(*listener.getsockname()))
            self.assertEqual(read_reply(control)[0][:3], b"\x05\x00\x00")
            with listener.accept()[0] as target:
                control.settimeout(2)
                target.settimeout(2)
                start = Barrier(4)

                def write_stream(sock, payload):
                    start.wait(timeout=2)
                    sock.sendall(payload)
                    sock.shutdown(socket.SHUT_WR)

                def read_stream(sock, payload):
                    start.wait(timeout=2)
                    self.assertEqual(recv_exact(sock, len(payload)), payload)
                    self.assertEqual(sock.recv(1), b"")

                jobs = [pool.submit(write_stream, control, upload),
                        pool.submit(write_stream, target, download),
                        pool.submit(read_stream, target, upload),
                        pool.submit(read_stream, control, download)]
                for job in jobs:
                    job.result(timeout=5)
        self.assertIsNone(self.proxy.poll())
        return upload_size + download_size


@unittest.skipUnless(FAULTS_ENABLED, "requires the fault-injection binary (--faults)")
class FaultClientSetupTests(ProxyTestCase):
    proxy_arguments = ("--fail-client-setup",)

    def test_failed_setup_releases_resources_and_backs_off(self):
        started = time.monotonic()
        for _ in range(6):
            with socket.create_connection((self.listen_host, self.port), 2) as failed:
                failed.settimeout(2)
                self.assert_closed(failed)
        with self.control() as first, self.control() as second:
            elapsed = time.monotonic() - started
            # Six resource failures must pause rather than spin through accepts.
            self.assertGreaterEqual(elapsed, 0.5)
            with socket.socket() as listener:
                listener.bind(("127.0.0.1", 0))
                listener.listen()
                listener.settimeout(2)
                first.sendall(b"\x05\x01\x00" + encode_address(
                    "127.0.0.1", listener.getsockname()[1]) + b"recovered request")
                self.assertEqual(read_reply(first)[0][:3], b"\x05\x00\x00")
                with listener.accept()[0] as target:
                    target.settimeout(2)
                    self.assertEqual(recv_exact(target, 17), b"recovered request")
                    target.sendall(b"recovered reply")
                    self.assertEqual(recv_exact(first, 15), b"recovered reply")
                self.assertIsNone(self.proxy.poll())
        # The native fixture asserts each socket, argument and slot was released.
        with ThreadPoolExecutor(max_workers=1) as pool:
            try:
                lines = pool.submit(lambda: [self.proxy.stderr.readline().strip()
                                             for _ in range(7)]).result(timeout=2)
            except BaseException:
                self.stop_proxy()
                raise
        self.assertEqual(lines, [f"Fault client setup: allocation {i}" for i in range(1, 4)]
                         + [f"Fault client setup: thread {i}" for i in range(1, 4)]
                         + ["Fault client setup: recovered"])


@unittest.skipUnless(FAULTS_ENABLED, "requires the fault-injection binary (--faults)")
class FaultTCPIOTests(ProxyTestCase):
    proxy_arguments = ("--short-tcp-io",)

    def test_simultaneous_streams_survive_short_io_and_transient_errors(self):
        payload_size = self.simultaneous_tcp_streams()
        with ThreadPoolExecutor(max_workers=1) as pool:
            try:
                line = pool.submit(self.proxy.stderr.readline).result(timeout=2).strip()
            except BaseException:
                self.stop_proxy()
                raise
        self.assertTrue(line.startswith("Fault TCP IO: "), line)
        counts = {key: int(value) for key, value in
                  (entry.split("=") for entry in line[len("Fault TCP IO: "):].split())}
        self.assertGreaterEqual(counts.pop("sent"), payload_size)
        self.assertGreaterEqual(counts.pop("received"), payload_size)
        self.assertEqual(set(counts), {"short_sends", "limited_receives", "send_interrupts",
                                      "send_blocks", "receive_interrupts", "receive_blocks"})
        for operation, count in counts.items():
            self.assertGreater(count, 0, f"{operation} was not exercised")
        self.assertIsNone(self.proxy.poll())


class CommandLineTests(unittest.TestCase):
    def test_help(self):
        for flag in ["--help", "-h"]:
            with self.subTest(flag=flag):
                result = subprocess.run([str(BINARY), flag], capture_output=True,
                                        text=True, timeout=3)
                self.assertEqual(result.returncode, 0)
                self.assertIn("Usage:", result.stdout)
                self.assertIn("port 0", result.stdout)
                self.assertEqual(result.stderr, "")

    def test_invalid_ports(self):
        for port in ["", "-1", "65536", "65537", "99999999999999999999",
                     "+1080", " 1080", "1080 ", "http", "1.5", "0x438"]:
            with self.subTest(port=port):
                result = subprocess.run([str(BINARY), "127.0.0.1", port],
                                        capture_output=True, text=True, timeout=3)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("Invalid port", result.stderr)

    def test_empty_listen_address(self):
        result = subprocess.run([str(BINARY), "", "0"], capture_output=True,
                                text=True, timeout=3)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Invalid listen address", result.stderr)

    def test_excess_arguments(self):
        result = subprocess.run([str(BINARY), "127.0.0.1", "0", "extra"],
                                capture_output=True, text=True, timeout=3)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Usage:", result.stderr)


class ProxyTests(ProxyTestCase):
    numeric_domains = (
        ("127.0.0.1", socket.AF_INET, "127.0.0.1", 1),
        ("::1", socket.AF_INET6, "::1", 4),
        ("::ffff:127.0.0.1", socket.AF_INET, "127.0.0.1", 1),
    )

    def numeric_tcp_round_trip(self, host, family, bind_host, reply_type):
        with socket.socket(family) as listener:
            try:
                listener.bind((bind_host, 0))
            except OSError:
                if family == socket.AF_INET6:
                    self.skipTest("IPv6 loopback is unavailable")
                raise
            listener.listen()
            listener.settimeout(2)
            with self.control() as control:
                control.settimeout(0.7)
                control.sendall(b"\x05\x01\x00" + encode_address(
                    host, listener.getsockname()[1], domain=True) + b"numeric request")
                control.shutdown(socket.SHUT_WR)
                self.assertEqual(read_reply(control)[0], bytes([5, 0, 0, reply_type]))
                with listener.accept()[0] as target:
                    target.settimeout(2)
                    self.assertEqual(recv_exact(target, 15), b"numeric request")
                    self.assertEqual(target.recv(1), b"")
                    target.sendall(b"numeric reply")
                    target.shutdown(socket.SHUT_WR)
                    self.assertEqual(recv_exact(control, 13), b"numeric reply")
                    self.assert_closed(control)

    def numeric_udp_round_trip(self, host, family, bind_host, reply_type):
        with self.control() as control, \
             socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client, \
             socket.socket(family, socket.SOCK_DGRAM) as target:
            try:
                target.bind((bind_host, 0))
            except OSError:
                if family == socket.AF_INET6:
                    self.skipTest("IPv6 loopback is unavailable")
                raise
            relay = self.associate(control)
            request = b"\x00\x00\x00" + encode_address(
                host, target.getsockname()[1], domain=True) + b"numeric payload"
            client.sendto(request, relay)
            target.settimeout(0.7)
            payload, outbound = target.recvfrom(100)
            self.assertEqual(payload, b"numeric payload")
            target.sendto(payload, outbound)
            client.settimeout(2)
            expected = b"\x00\x00\x00" + encode_address(
                bind_host, target.getsockname()[1]) + payload
            self.assertEqual(expected[3], reply_type)
            self.assertEqual(client.recvfrom(100)[0], expected)

    def test_tcp_numeric_domain_and_half_close(self):
        for case in self.numeric_domains:
            with self.subTest(host=case[0]):
                self.numeric_tcp_round_trip(*case)

    def test_udp_numeric_domain(self):
        for case in self.numeric_domains:
            with self.subTest(host=case[0]):
                self.numeric_udp_round_trip(*case)

    def test_authentication_rejection(self):
        with socket.create_connection(("127.0.0.1", self.port), 2) as control:
            control.sendall(b"\x05\x01\x02")
            self.assertEqual(recv_exact(control, 2), b"\x05\xff")
            self.assert_closed(control)

    def test_maximum_authentication_methods(self):
        with socket.create_connection((self.listen_host, self.port), 2) as control:
            control.settimeout(2)
            control.sendall(b"\x05\xff" + b"\x02" * 254 + b"\x00")
            self.assertEqual(recv_exact(control, 2), b"\x05\x00")
            control.sendall(b"\x05\x02\x00\x01")
            self.assertEqual(read_reply(control)[0][:3], b"\x05\x07\x00")
            self.assert_closed(control)

    def test_truncated_greeting(self):
        for greeting in [b"\x05", b"\x05\x01", b"\x05\xff" + b"\x02" * 254]:
            with self.subTest(greeting=greeting), \
                 socket.create_connection((self.listen_host, self.port), 2) as control:
                control.settimeout(2)
                control.sendall(greeting)
                control.shutdown(socket.SHUT_WR)
                self.assert_closed(control)

    def test_unsupported_command_and_address(self):
        for request, status in [(b"\x05\x02\x00\x01", 7),
                                (b"\x05\x01\x00\x09", 8)]:
            with self.subTest(status=status), self.control() as control:
                control.sendall(request)
                header, _ = read_reply(control)
                self.assertEqual(header[:3], bytes([5, status, 0]))
                self.assert_closed(control)

    def test_malformed_request(self):
        for request in [b"\x04\x01\x00\x01", b"\x05\x01\x01\x01",
                        b"\x05\x01\x00\x03\x00",
                        b"\x05\x01\x00\x03\x03a\x00b"]:
            with self.subTest(request=request), self.control() as control:
                control.sendall(request)
                self.assert_closed(control)

    def test_connection_refused(self):
        with self.control() as control:
            with socket.socket() as reservation:
                reservation.bind(("127.0.0.1", 0))
                target_port = reservation.getsockname()[1]
            # Close the reservation before connecting: macOS can leave a connect
            # pending when the destination socket is bound but not listening.
            control.sendall(b"\x05\x01\x00" +
                            encode_address("127.0.0.1", target_port))
            header, _ = read_reply(control)
            self.assertEqual(header[:3], b"\x05\x05\x00")
            self.assert_closed(control)

    def test_domain_connect_and_pipelined_payload(self):
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            listener.listen()
            listener.settimeout(2)
            with socket.create_connection(("127.0.0.1", self.port), 2) as control:
                control.settimeout(5)  # Windows can take over 2s to refuse the first address.
                request = (GREETING + b"\x05\x01\x00" +
                           encode_address("localhost", listener.getsockname()[1], domain=True))
                # Split protocol fields, then pipeline application data with the request.
                control.sendall(request[:1])
                control.sendall(request[1:5])
                control.sendall(request[5:] + b"pipelined")
                self.assertEqual(recv_exact(control, 2), b"\x05\x00")
                self.assertEqual(read_reply(control)[0][:2], b"\x05\x00")
                with listener.accept()[0] as target:
                    target.settimeout(2)
                    self.assertEqual(recv_exact(target, 9), b"pipelined")

    def test_pipelined_handshake_and_half_close(self):
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            listener.listen()
            listener.settimeout(2)
            with socket.create_connection((self.listen_host, self.port), 2) as control:
                control.settimeout(2)
                control.sendall(GREETING + b"\x05\x01\x00" +
                                encode_address("127.0.0.1", listener.getsockname()[1]) +
                                b"request before FIN")
                control.shutdown(socket.SHUT_WR)
                self.assertEqual(recv_exact(control, 2), b"\x05\x00")
                self.assertEqual(read_reply(control)[0][:3], b"\x05\x00\x00")
                with listener.accept()[0] as target:
                    target.settimeout(2)
                    self.assertEqual(recv_exact(target, 18), b"request before FIN")
                    self.assertEqual(target.recv(1), b"")
                    target.sendall(b"response after FIN")
                    target.shutdown(socket.SHUT_WR)
                    self.assertEqual(recv_exact(control, 18), b"response after FIN")
                    self.assert_closed(control)

    def test_ipv6_connect(self):
        with socket.socket(socket.AF_INET6) as listener:
            try:
                listener.bind(("::1", 0))
            except OSError:
                self.skipTest("IPv6 loopback is unavailable")
            listener.listen()
            listener.settimeout(2)
            with self.control() as control:
                control.sendall(b"\x05\x01\x00" +
                                encode_address("::1", listener.getsockname()[1]))
                header, endpoint = read_reply(control)
                self.assertEqual(header, b"\x05\x00\x00\x04")
                self.assertEqual(endpoint[0], "::1")
                with listener.accept()[0] as target:
                    target.settimeout(2)
                    target.sendall(b"ipv6")
                    self.assertEqual(recv_exact(control, 4), b"ipv6")

    def test_tcp_ipv4_mapped_ipv6_target(self):
        for domain in [False, True]:
            with self.subTest(domain=domain), socket.socket() as listener:
                listener.bind(("127.0.0.1", 0))
                listener.listen()
                listener.settimeout(2)
                with self.control() as control:
                    control.sendall(b"\x05\x01\x00" +
                                    encode_address("::ffff:127.0.0.1",
                                                   listener.getsockname()[1], domain=domain))
                    header, endpoint = read_reply(control)
                    self.assertEqual(header, b"\x05\x00\x00\x01")
                    self.assertEqual(endpoint[0], "127.0.0.1")
                    with listener.accept()[0] as target:
                        target.settimeout(2)
                        control.sendall(b"mapped request")
                        self.assertEqual(recv_exact(target, 14), b"mapped request")
                        target.sendall(b"mapped reply")
                        self.assertEqual(recv_exact(control, 12), b"mapped reply")

    def test_tcp_backpressure_keeps_reverse_direction_live(self):
        with socket.socket() as listener:
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 16384)
            listener.bind(("127.0.0.1", 0))
            listener.listen()
            listener.settimeout(2)
            with ThreadPoolExecutor(max_workers=1) as pool, self.control() as control:
                control.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 16384)
                control.sendall(b"\x05\x01\x00" +
                                encode_address("127.0.0.1", listener.getsockname()[1]))
                self.assertEqual(read_reply(control)[0][:2], b"\x05\x00")
                with listener.accept()[0] as target:
                    target.settimeout(2)
                    target.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4096)

                    def upload():
                        # Small writes also bound Winsock's queued send allocations.
                        for _ in range(128):
                            control.sendall(b"x" * 65536)

                    sender = pool.submit(upload)
                    time.sleep(0.2)
                    if sender.done():
                        sender.result()
                    self.assertFalse(sender.done(), "upload must exceed socket buffers")
                    target.sendall(b"reverse")
                    control.settimeout(1)
                    self.assertEqual(recv_exact(control, 7), b"reverse")
                    control.shutdown(socket.SHUT_RDWR)

    def test_tcp_simultaneous_streams_and_half_close(self):
        self.simultaneous_tcp_streams()

    def test_tcp_large_payload_drains_before_half_close(self):
        # An aperiodic pattern exposes byte loss or reordering at buffer wraps.
        size = 1024 * 1024 + 137
        payload = random.Random(0).getrandbits(size * 8).to_bytes(size, "little")
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            listener.listen()
            listener.settimeout(2)
            with ThreadPoolExecutor(max_workers=1) as pool, self.control() as control:
                control.sendall(b"\x05\x01\x00" +
                                encode_address("127.0.0.1", listener.getsockname()[1]))
                self.assertEqual(read_reply(control)[0][:2], b"\x05\x00")
                with listener.accept()[0] as target:
                    target.settimeout(5)

                    def upload():
                        control.sendall(payload)
                        control.shutdown(socket.SHUT_WR)

                    sender = pool.submit(upload)
                    self.assertEqual(recv_exact(target, len(payload)), payload)
                    self.assertEqual(target.recv(1), b"")
                    sender.result(timeout=5)

                    def download():
                        target.sendall(payload)
                        target.shutdown(socket.SHUT_WR)

                    sender = pool.submit(download)
                    self.assertEqual(recv_exact(control, len(payload)), payload)
                    self.assertEqual(control.recv(1), b"")
                    sender.result(timeout=5)

    def fill_tcp_direction(self, source, destination):
        source.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 16384)
        source.setblocking(False)
        deadline = time.monotonic() + 2
        blocked_at = None
        sent = 0
        while time.monotonic() < deadline:
            try:
                sent += source.send(b"x" * 65536)
                blocked_at = None
            except BlockingIOError:
                now = time.monotonic()
                if blocked_at is None:
                    blocked_at = now
                if now - blocked_at >= 0.15:
                    break
                select.select([], [source], [], 0.02)
        else:
            self.fail("upload did not stall while the receiver stopped reading")
        self.assertGreater(sent, 16384)
        # Confirm the relay is still active and its reverse path works.
        destination.sendall(b"reverse")
        source.settimeout(0.5)
        self.assertEqual(recv_exact(source, 7), b"reverse")
        return sent

    def reset_under_backpressure(self, upstream):
        with socket.socket() as listener:
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4096)
            listener.bind(("127.0.0.1", 0))
            listener.listen()
            listener.settimeout(2)
            request = b"\x05\x01\x00" + encode_address(*listener.getsockname())
            with self.control() as control:
                control.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4096)
                control.sendall(request)
                self.assertEqual(read_reply(control)[0][:2], b"\x05\x00")
                with listener.accept()[0] as target:
                    target.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4096)
                    source = target if upstream else control
                    destination = control if upstream else target
                    self.fill_tcp_direction(source, destination)
                    with self.control() as other:
                        other.sendall(request)
                        self.assertEqual(read_reply(other)[0][:2], b"\x05\x00")
                        with listener.accept()[0] as held:
                            held.settimeout(2)
                            source.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER,
                                              struct.pack("HH" if sys.platform == "win32" else "ii", 1, 0))
                            source.close()
                            # Keep the original receiver stalled and the other slot occupied.
                            deadline = time.monotonic() + 0.4
                            replacement = None
                            while time.monotonic() < deadline:
                                candidate = socket.socket()
                                candidate.settimeout(max(0.001, deadline - time.monotonic()))
                                try:
                                    candidate.connect((self.listen_host, self.port))
                                    candidate.sendall(GREETING)
                                    if recv_exact(candidate, 2) == b"\x05\x00":
                                        replacement = candidate
                                        self.addCleanup(candidate.close)
                                        break
                                except (OSError, EOFError):
                                    pass
                                candidate.close()
                                time.sleep(0.005)
                            self.assertIsNotNone(replacement, "reset relay retained its client slot")
                            self.assertLess(time.monotonic(), deadline)
                            # A live second session rules out its timeout causing recovery.
                            other.sendall(b"held")
                            self.assertEqual(recv_exact(held, 4), b"held")
                            with replacement:
                                replacement.settimeout(2)
                                replacement.sendall(request + b"new request")
                                self.assertEqual(read_reply(replacement)[0][:2], b"\x05\x00")
                                with listener.accept()[0] as resumed:
                                    resumed.settimeout(2)
                                    self.assertEqual(recv_exact(resumed, 11), b"new request")
                                    resumed.sendall(b"new reply")
                                    self.assertEqual(recv_exact(replacement, 9), b"new reply")

    @requires_test_limits
    def test_tcp_client_reset_under_backpressure_releases_slot(self):
        self.reset_under_backpressure(upstream=False)

    @requires_test_limits
    def test_tcp_target_reset_under_backpressure_releases_slot(self):
        self.reset_under_backpressure(upstream=True)

    def test_tcp_half_close_under_backpressure(self):
        for upstream in (False, True):
            with self.subTest(upstream=upstream), socket.socket() as listener:
                # A tiny negotiated TCP window can take longer than the 3-second
                # idle limit to drain kernel queues after the relay sent its FIN.
                listener.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 65536)
                listener.bind(("127.0.0.1", 0))
                listener.listen()
                listener.settimeout(2)
                with self.control() as control:
                    control.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 65536)
                    control.sendall(b"\x05\x01\x00" + encode_address(*listener.getsockname()))
                    self.assertEqual(read_reply(control)[0][:2], b"\x05\x00")
                    with listener.accept()[0] as target:
                        target.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 65536)
                        source = target if upstream else control
                        destination = control if upstream else target
                        sent = self.fill_tcp_direction(source, destination)
                        source.shutdown(socket.SHUT_WR)
                        # Several periodic reset checks must preserve a valid FIN.
                        time.sleep(0.2)
                        destination.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 262144)
                        destination.settimeout(3)
                        self.assertEqual(recv_exact(destination, sent), b"x" * sent)
                        self.assertEqual(destination.recv(1), b"")
                        destination.sendall(b"after FIN")
                        destination.shutdown(socket.SHUT_WR)
                        source.settimeout(2)
                        self.assertEqual(recv_exact(source, 9), b"after FIN")
                        self.assertEqual(source.recv(1), b"")

    def test_udp_invalid_packet_does_not_pin_client(self):
        with self.control() as control, \
             socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as rogue, \
             socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client, \
             socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as target:
            relay = self.associate(control)
            rogue.bind(("127.0.0.1", 0))
            client.bind(("127.0.0.1", 0))
            target.bind(("127.0.0.1", 0))
            target.settimeout(2)
            malformed = [b"", b"invalid", b"\x00\x00\x00\x09",
                         b"\x01\x00\x00\x01" + b"\x00" * 6,
                         b"\x00\x00\x00\x01\x7f\x00\x00\x01\x00",
                         b"\x00\x00\x00\x04" + b"\x00" * 17,
                         b"\x00\x00\x00\x03\x00\x00\x00",
                         b"\x00\x00\x00\x03\x03a\x00b\x00\x01"]
            for packet in malformed:
                rogue.sendto(packet, relay)
            time.sleep(0.1)
            request = b"\x00\x00\x00" + encode_address(*target.getsockname()) + b"valid"
            client.sendto(request, relay)
            self.assertEqual(target.recvfrom(100)[0], b"valid")
            rogue.sendto(request, relay)
            target.settimeout(0.2)
            with self.assertRaises(socket.timeout):
                target.recvfrom(100)

    def test_udp_requested_port_and_fragment_validation(self):
        with self.control() as control, \
             socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as rogue, \
             socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client, \
             socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as target:
            client.bind(("127.0.0.1", 0))
            rogue.bind(("127.0.0.1", 0))
            target.bind(("127.0.0.1", 0))
            relay = self.associate(control, client.getsockname()[1])
            request = b"\x00\x00\x00" + encode_address(*target.getsockname()) + b"valid"
            rogue.sendto(request, relay)
            client.sendto(b"\x00\x00\x01" + request[3:], relay)
            target.settimeout(0.2)
            with self.assertRaises(socket.timeout):
                target.recvfrom(100)
            client.sendto(request, relay)
            target.settimeout(2)
            self.assertEqual(target.recvfrom(100)[0], b"valid")

    def test_udp_failed_forward_does_not_pin_client(self):
        with self.control() as control, \
             socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as rogue, \
             socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client, \
             socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as target:
            relay = self.associate(control)
            rogue.bind(("127.0.0.1", 0))
            client.bind(("127.0.0.1", 0))
            target.bind(("127.0.0.1", 0))
            # Broadcast sends fail because the proxy does not enable SO_BROADCAST.
            for domain in [False, True]:
                rogue.sendto(b"\x00\x00\x00" +
                             encode_address("255.255.255.255", 12345, domain=domain) + b"unsendable",
                             relay)
            time.sleep(0.1)
            request = b"\x00\x00\x00" + encode_address(*target.getsockname()) + b"valid"
            client.sendto(request, relay)
            target.settimeout(2)
            data, outbound = target.recvfrom(100)
            self.assertEqual(data, b"valid")
            target.sendto(data, outbound)
            client.settimeout(2)
            self.assertEqual(client.recvfrom(100)[0], request)

    @requires_test_limits
    def test_udp_invalid_traffic_does_not_extend_idle_timeout(self):
        with self.control() as control, \
             socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
            relay = self.associate(control)
            start = time.monotonic()
            control.settimeout(0.1)
            while time.monotonic() - start < 4:
                client.sendto(b"invalid", relay)
                try:
                    self.assertEqual(control.recv(1), b"")
                    break
                except socket.timeout:
                    continue
                except ConnectionError:
                    break
            else:
                self.fail("invalid UDP traffic kept an idle association alive")
            self.assertGreaterEqual(time.monotonic() - start, 2.5)

    def test_udp_control_close_ends_association(self):
        with self.control() as control, \
             socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client, \
             socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as target:
            relay = self.associate(control)
            target.bind(("127.0.0.1", 0))
            target.settimeout(0.3)
            control.close()
            time.sleep(0.1)
            client.sendto(b"\x00\x00\x00" + encode_address(*target.getsockname()) + b"late", relay)
            with self.assertRaises(socket.timeout):
                target.recvfrom(100)

    def test_udp_domain_and_empty_payload(self):
        with self.control() as control, \
             socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client, \
             socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as target:
            relay = self.associate(control)
            client.bind(("127.0.0.1", 0))
            target.bind(("127.0.0.1", 0))
            target.settimeout(2)
            client.sendto(b"\x00\x00\x00" +
                          encode_address("127.0.0.1", target.getsockname()[1], domain=True), relay)
            data, outbound = target.recvfrom(100)
            self.assertEqual(data, b"")
            target.sendto(b"", outbound)
            client.settimeout(2)
            self.assertEqual(client.recvfrom(100)[0],
                             b"\x00\x00\x00" + encode_address(*target.getsockname()))

    def large_udp_round_trip(self, family, host):
        with self.control() as control, \
             socket.socket(socket.AF_INET6 if ":" in self.listen_host else socket.AF_INET,
                           socket.SOCK_DGRAM) as client, \
             socket.socket(family, socket.SOCK_DGRAM) as target:
            relay = self.associate(control)
            try:
                target.bind((host, 0))
            except OSError:
                if family == socket.AF_INET6:
                    self.skipTest("IPv6 loopback is unavailable")
                raise
            for sock in (client, target):
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 131072)
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 131072)
            target.settimeout(2)
            client.settimeout(2)
            header = b"\x00\x00\x00" + encode_address(host, target.getsockname()[1])
            # 65,485 bytes plus the largest SOCKS header fits IPv4's UDP limit.
            for size in (0, 8192, 16384, 49152, 65485):
                payload = random.Random(size).getrandbits(size * 8).to_bytes(size, "little")
                with self.subTest(size=size, target_family=family):
                    client.sendto(header + payload, relay)
                    data, outbound = target.recvfrom(65536)
                    self.assertEqual(data, payload)
                    target.sendto(data, outbound)
                    self.assertEqual(client.recvfrom(65536)[0], header + payload)

    def test_udp_numeric_payload_sizes(self):
        for family, host in ((socket.AF_INET, "127.0.0.1"), (socket.AF_INET6, "::1")):
            self.large_udp_round_trip(family, host)

    def test_udp_domain_case_variants_and_destination_ports(self):
        with ExitStack() as stack:
            control = stack.enter_context(self.control())
            client = stack.enter_context(socket.socket(socket.AF_INET, socket.SOCK_DGRAM))
            client.settimeout(2)
            relay = self.associate(control)
            targets = []
            for _ in range(2):
                ipv4 = stack.enter_context(socket.socket(socket.AF_INET, socket.SOCK_DGRAM))
                ipv4.bind(("127.0.0.1", 0))
                port = ipv4.getsockname()[1]
                families = [ipv4]
                try:
                    ipv6 = stack.enter_context(socket.socket(socket.AF_INET6, socket.SOCK_DGRAM))
                    ipv6.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
                    ipv6.bind(("::1", port))
                    families.append(ipv6)
                except OSError:
                    pass
                targets.append((port, families))
            all_targets = [sock for _, families in targets for sock in families]
            for host in ("localhost", "LoCaLhOsT", "LOCALHOST", "localhost"):
                for port, families in targets:
                    with self.subTest(host=host, port=port):
                        payload = host.encode("ascii") + struct.pack("!H", port)
                        client.sendto(b"\x00\x00\x00" + encode_address(
                            host, port, domain=True) + payload, relay)
                        ready, _, _ = select.select(all_targets, [], [], 2)
                        self.assertTrue(ready, "localhost UDP request was not delivered")
                        self.assertIn(ready[0], families, "request reached the wrong destination port")
                        data, outbound = ready[0].recvfrom(100)
                        self.assertEqual(data, payload)
                        ready[0].sendto(data, outbound)
                        address = ready[0].getsockname()
                        self.assertEqual(client.recvfrom(100)[0], b"\x00\x00\x00" +
                                         encode_address(address[0], address[1]) + payload)

    def test_udp_numeric_domain_keeps_destination_ports_separate(self):
        with self.control() as control, \
             socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client, \
             socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as first, \
             socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as second:
            relay = self.associate(control)
            client.settimeout(2)
            for target in [first, second]:
                target.bind(("127.0.0.1", 0))
                target.settimeout(2)
            for host in ["127.0.0.1", "::ffff:127.0.0.1"]:
                for target in [first, second, first, second]:
                    with self.subTest(host=host, port=target.getsockname()[1]):
                        payload = struct.pack("!H", target.getsockname()[1])
                        request = (b"\x00\x00\x00" +
                                   encode_address(host, target.getsockname()[1], domain=True) +
                                   payload)
                        client.sendto(request, relay)
                        data, outbound = target.recvfrom(100)
                        self.assertEqual(data, payload)
                        target.sendto(data, outbound)
                        self.assertEqual(client.recvfrom(100)[0], b"\x00\x00\x00" +
                                         encode_address(*target.getsockname()) + payload)

    def test_udp_ipv6_target(self):
        with self.control() as control, \
             socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client, \
             socket.socket(socket.AF_INET6, socket.SOCK_DGRAM) as target:
            try:
                target.bind(("::1", 0))
            except OSError:
                self.skipTest("IPv6 loopback is unavailable")
            relay = self.associate(control)
            target.settimeout(2)
            request_address = encode_address("::1", target.getsockname()[1])
            client.sendto(b"\x00\x00\x00" + request_address + b"ipv6", relay)
            data, outbound = target.recvfrom(100)
            self.assertEqual(data, b"ipv6")
            target.sendto(data, outbound)
            client.settimeout(2)
            self.assertEqual(client.recvfrom(100)[0], b"\x00\x00\x00" + request_address + b"ipv6")

    def test_udp_ipv4_mapped_ipv6_target(self):
        with self.control() as control, \
             socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client, \
             socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as target:
            relay = self.associate(control)
            target.bind(("127.0.0.1", 0))
            target.settimeout(2)
            client.settimeout(2)
            for domain in [False, True]:
                with self.subTest(domain=domain):
                    client.sendto(b"\x00\x00\x00" +
                                  encode_address("::ffff:127.0.0.1", target.getsockname()[1],
                                                 domain=domain) + b"mapped", relay)
                    data, outbound = target.recvfrom(100)
                    self.assertEqual(data, b"mapped")
                    target.sendto(data, outbound)
                    self.assertEqual(client.recvfrom(100)[0], b"\x00\x00\x00" +
                                     encode_address(*target.getsockname()) + b"mapped")

    @requires_test_limits
    def test_udp_control_data_does_not_extend_idle_timeout(self):
        with self.control() as control:
            self.associate(control)
            start = time.monotonic()
            control.settimeout(0.1)
            while time.monotonic() - start < 4:
                try:
                    control.sendall(b"ignored control data")
                    if control.recv(1) == b"":
                        break
                except socket.timeout:
                    continue
                except ConnectionError:
                    break
            else:
                self.fail("TCP control data kept an idle UDP association alive")
            self.assertGreaterEqual(time.monotonic() - start, 2.5)

    def test_udp_valid_traffic_refreshes_idle_timeout(self):
        with self.control() as control, \
             socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client, \
             socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as target:
            relay = self.associate(control)
            target.bind(("127.0.0.1", 0))
            target.settimeout(2)
            client.settimeout(2)
            request = b"\x00\x00\x00" + encode_address(*target.getsockname()) + b"active"
            for _ in range(5):
                time.sleep(0.8)
                client.sendto(request, relay)
                data, outbound = target.recvfrom(100)
                self.assertEqual(data, b"active")
                target.sendto(data, outbound)
                self.assertEqual(client.recvfrom(100)[0], request)

    def test_udp_source_validation(self):
        with self.control() as control, \
             socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client, \
             socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as target, \
             socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as rogue:
            control.sendall(b"\x05\x03\x00\x01" + socket.inet_aton("0.0.0.0") + b"\x00\x00")
            reply = recv_exact(control, 10)
            self.assertEqual(reply[:4], b"\x05\x00\x00\x01")
            relay = (socket.inet_ntoa(reply[4:8]), int.from_bytes(reply[8:10], "big"))

            client.bind(("127.0.0.1", 0))
            target.bind(("127.0.0.1", 0))
            rogue.bind(("127.0.0.1", 0))
            target.settimeout(2)
            target_port = target.getsockname()[1]
            request = (b"\x00\x00\x00\x01" + socket.inet_aton("127.0.0.1")
                       + struct.pack("!H", target_port) + b"request")
            client.sendto(request, relay)
            data, outbound = target.recvfrom(100)
            self.assertEqual(data, b"request")

            rogue.sendto(b"unsolicited", outbound)
            client.settimeout(0.3)
            with self.assertRaises(socket.timeout):
                client.recvfrom(100)

            target.sendto(b"legitimate", outbound)
            client.settimeout(2)
            response, _ = client.recvfrom(100)
            self.assertEqual(response[:4], b"\x00\x00\x00\x01")
            self.assertEqual(response[10:], b"legitimate")
            self.assertEqual(int.from_bytes(response[8:10], "big"), target_port)

    @requires_test_limits
    def test_client_limit(self):
        with self.control() as first, self.control() as second:
            with socket.create_connection(("127.0.0.1", self.port), 2) as blocked:
                blocked.settimeout(2)
                try:
                    blocked.sendall(GREETING)
                    self.assertEqual(blocked.recv(2), b"")
                except ConnectionError:
                    pass  # A closed connection can produce a reset instead of EOF.

            first.close()
            deadline = time.monotonic() + 2
            while True:
                try:
                    with self.control():
                        break
                except (EOFError, ConnectionError):
                    if time.monotonic() >= deadline:
                        raise
                    time.sleep(0.02)

    @requires_test_limits
    def test_handshake_deadline(self):
        with self.control() as control:
            control.sendall(b"\x05")
            time.sleep(0.6)
            control.sendall(b"\x01")
            time.sleep(0.6)
            try:
                self.assertEqual(control.recv(1), b"")
            except ConnectionError:
                pass  # Windows can reset a connection with unread request bytes.

    @requires_test_limits
    def test_tcp_idle_timeout(self):
        with socket.socket() as target_listener:
            target_listener.bind(("127.0.0.1", 0))
            target_listener.listen()
            target_listener.settimeout(2)
            with self.control() as control:
                target_port = target_listener.getsockname()[1]
                control.sendall(b"\x05\x01\x00\x01" + socket.inet_aton("127.0.0.1")
                                + struct.pack("!H", target_port))
                self.assertEqual(recv_exact(control, 10)[:2], b"\x05\x00")
                with target_listener.accept()[0] as target:
                    target.settimeout(5)
                    control.sendall(b"hello")
                    self.assertEqual(recv_exact(target, 5), b"hello")
                    target.sendall(b"world")
                    self.assertEqual(recv_exact(control, 5), b"world")
                    start = time.monotonic()
                    self.assertEqual(control.recv(1), b"")
                    self.assertGreaterEqual(time.monotonic() - start, 2.5)

    def test_tcp_half_close(self):
        with socket.socket() as target_listener:
            target_listener.bind(("127.0.0.1", 0))
            target_listener.listen()
            target_listener.settimeout(2)
            with self.control() as control:
                target_port = target_listener.getsockname()[1]
                control.sendall(b"\x05\x01\x00\x01" + socket.inet_aton("127.0.0.1")
                                + struct.pack("!H", target_port))
                self.assertEqual(recv_exact(control, 10)[:2], b"\x05\x00")
                with target_listener.accept()[0] as target:
                    target.settimeout(2)
                    control.shutdown(socket.SHUT_WR)
                    self.assertEqual(target.recv(1), b"")
                    target.sendall(b"tail")
                    self.assertEqual(recv_exact(control, 4), b"tail")


@unittest.skipUnless(FAULTS_ENABLED, "requires the fault-injection binary (--faults)")
class FaultProxyTests(ProxyTestCase):
    """Checks requiring the resolver and socket failures in test_faults.c."""

    def reset_control(self, control):
        linger = struct.pack("HH" if sys.platform == "win32" else "ii", 1, 0)
        control.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, linger)
        control.close()

    def wait_for_held_dns(self):
        with ThreadPoolExecutor(max_workers=1) as pool:
            try:
                lines = pool.submit(lambda: [self.proxy.stderr.readline().strip()
                                             for _ in range(2)]).result(timeout=2)
            except BaseException:
                self.stop_proxy()  # Unblock a pending diagnostic read before joining.
                raise
        self.assertEqual(set(lines), {"Fault DNS held: 0", "Fault DNS held: 1"})

    def assert_service_after_reset(self):
        deadline = time.monotonic() + 0.4
        controls = []
        while len(controls) < 2 and time.monotonic() < deadline:
            candidate = None
            try:
                candidate = socket.create_connection(("127.0.0.1", self.port), 0.1)
                self.addCleanup(candidate.close)
                candidate.settimeout(0.1)
                candidate.sendall(GREETING)
                self.assertEqual(recv_exact(candidate, 2), b"\x05\x00")
                controls.append(candidate)
            except (OSError, EOFError):
                if candidate is not None:
                    candidate.close()
                time.sleep(0.01)
        if len(controls) != 2:
            self.fail("reset clients retained client slots during DNS waiting")
        self.assertLess(time.monotonic(), deadline, "client slots recovered after the deadline")
        with controls[0] as control, controls[1], socket.socket() as target:
            target.bind(("127.0.0.1", 0))
            target.listen()
            target.settimeout(1)
            control.settimeout(1)
            control.sendall(b"\x05\x01\x00" + encode_address(*target.getsockname()) + b"available")
            self.assertEqual(read_reply(control)[0][:3], b"\x05\x00\x00")
            with target.accept()[0] as received:
                received.settimeout(1)
                self.assertEqual(recv_exact(received, 9), b"available")
                received.sendall(b"reply")
                self.assertEqual(recv_exact(control, 5), b"reply")

    def test_tcp_reset_during_dns_releases_client_slots(self):
        with self.control() as first, self.control() as second:
            request = b"\x05\x01\x00" + encode_address("reset.test", 9, domain=True)
            first.sendall(request)
            second.sendall(request + b"pending payload" * 2048)
            self.wait_for_held_dns()  # Both system resolvers are blocked before RST.
            time.sleep(0.05)
            self.reset_control(first)
            self.reset_control(second)
        self.assert_service_after_reset()

    def test_tcp_reset_while_dns_slots_full_releases_client_slots(self):
        self.occupy_resolver_slots()
        with self.control() as first, self.control() as second:
            request = b"\x05\x01\x00" + encode_address("delayed.test", 9, domain=True)
            first.sendall(request)
            second.sendall(request + b"pending payload" * 2048)
            time.sleep(0.1)
            self.reset_control(first)
            self.reset_control(second)
        self.assert_service_after_reset()

    def test_tcp_reset_during_dns_does_not_connect_late(self):
        for payload in (b"", b"pending payload" * 2048):
            with self.subTest(payload_bytes=len(payload)), socket.socket() as target:
                target.bind(("127.0.0.1", 0))
                target.listen()
                with self.control() as control:
                    control.sendall(b"\x05\x01\x00" + encode_address(
                        "delayed.test", target.getsockname()[1], domain=True) + payload)
                    time.sleep(0.1)
                    self.reset_control(control)
                # DNS returns at 600 ms, still within the one-second budget.
                target.settimeout(0.8)
                with self.assertRaises(socket.timeout):
                    with target.accept()[0]:
                        pass

    def occupy_resolver_slots(self):
        with self.control() as first, self.control() as second:
            for control in (first, second):
                control.sendall(b"\x05\x01\x00" + encode_address("held.test", 9, domain=True))
            for control in (first, second):
                self.assertEqual(read_reply(control)[0][:3], b"\x05\x04\x00")
                self.assert_closed(control)
        # Let client threads finish; the held resolver workers retain both slots.
        time.sleep(0.05)

    def test_tcp_numeric_domain_with_dns_slots_full(self):
        self.occupy_resolver_slots()
        for case in ProxyTests.numeric_domains:
            with self.subTest(host=case[0]):
                ProxyTests.numeric_tcp_round_trip(self, *case)

    def test_udp_numeric_domain_with_dns_slots_full(self):
        self.occupy_resolver_slots()
        for case in ProxyTests.numeric_domains:
            with self.subTest(host=case[0]):
                ProxyTests.numeric_udp_round_trip(self, *case)

    def test_udp_case_variants_share_cache_with_dns_slots_full(self):
        with self.control() as control, \
             socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client, \
             socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as first, \
             socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as second:
            relay = self.associate(control)
            client.settimeout(0.6)
            for target in (first, second):
                target.bind(("127.0.0.1", 0))
                target.settimeout(0.6)

            def round_trip(host, target):
                payload = host.encode("ascii") + struct.pack("!H", target.getsockname()[1])
                client.sendto(b"\x00\x00\x00" + encode_address(
                    host, target.getsockname()[1], domain=True) + payload, relay)
                data, outbound = target.recvfrom(100)
                self.assertEqual(data, payload)
                target.sendto(data, outbound)
                self.assertEqual(client.recvfrom(100)[0], b"\x00\x00\x00" +
                                 encode_address(*target.getsockname()) + payload)

            round_trip("CacheCase.Test", first)
            # The UDP association uses one client slot, so hold DNS workers
            # through the remaining slot in sequence. Refresh UDP idle time.
            for _ in range(2):
                with self.control() as held:
                    held.sendall(b"\x05\x01\x00" + encode_address("held.test", 9, domain=True))
                    self.assertEqual(read_reply(held)[0][:3], b"\x05\x04\x00")
                    self.assert_closed(held)
                time.sleep(0.05)
                round_trip("CacheCase.Test", first)
            for host, target in (("cachecase.test", second), ("CACHECASE.TEST", first)):
                with self.subTest(host=host, port=target.getsockname()[1]):
                    round_trip(host, target)

    def test_udp_control_close_during_dns_drops_datagram(self):
        for ignored_data in (b"", b"ignored" * 8192):
            with self.subTest(control_bytes=len(ignored_data)), self.control() as control, \
                 socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client, \
                 socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as target:
                relay = self.associate(control)
                target.bind(("127.0.0.1", 0))
                request = b"\x00\x00\x00" + encode_address(
                    "delayed.test", target.getsockname()[1], domain=True) + b"cancelled"
                client.sendto(request, relay)
                time.sleep(0.1)
                if ignored_data:
                    control.sendall(ignored_data)
                control.close()
                # This lookup finishes within the DNS budget; closure must cancel it.
                target.settimeout(1.1)
                with self.assertRaises(socket.timeout):
                    target.recvfrom(100)

    def test_udp_control_half_close_during_dns_is_prompt(self):
        with self.control() as control, \
             socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client, \
             socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as target:
            relay = self.associate(control)
            target.bind(("127.0.0.1", 0))
            client.sendto(b"\x00\x00\x00" + encode_address(
                "slow.test", target.getsockname()[1], domain=True) + b"cancelled", relay)
            time.sleep(0.1)
            control.shutdown(socket.SHUT_WR)
            control.settimeout(0.4)
            self.assert_closed(control)
            # Keep the destination open beyond the cancelled worker's completion.
            target.settimeout(2.1)
            with self.assertRaises(socket.timeout):
                target.recvfrom(100)

    def test_udp_control_data_during_dns_preserves_payload(self):
        with self.control() as control, \
             socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client, \
             socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as target:
            relay = self.associate(control)
            target.bind(("127.0.0.1", 0))
            request = b"\x00\x00\x00" + encode_address(
                "delayed.test", target.getsockname()[1], domain=True) + b"original payload"
            client.sendto(request, relay)
            time.sleep(0.1)
            control.sendall(b"ignored control data" * 4096)
            target.settimeout(1.5)
            payload, outbound = target.recvfrom(100)
            self.assertEqual(payload, b"original payload")
            target.sendto(payload, outbound)
            client.settimeout(2)
            self.assertEqual(client.recvfrom(100)[0], b"\x00\x00\x00" +
                             encode_address(*target.getsockname()) + payload)

    def test_tcp_domain_half_close_during_dns(self):
        for payload in (b"before FIN", b"pending payload" * 2048):
            with self.subTest(payload_bytes=len(payload)), socket.socket() as listener:
                listener.bind(("127.0.0.1", 0))
                listener.listen()
                listener.settimeout(2)
                with self.control() as control:
                    control.sendall(b"\x05\x01\x00" + encode_address(
                        "delayed.test", listener.getsockname()[1], domain=True) + payload)
                    control.shutdown(socket.SHUT_WR)
                    self.assertEqual(read_reply(control)[0][:3], b"\x05\x00\x00")
                    with listener.accept()[0] as target:
                        target.settimeout(2)
                        self.assertEqual(recv_exact(target, len(payload)), payload)
                        self.assertEqual(target.recv(1), b"")
                        target.sendall(b"after FIN")
                        target.shutdown(socket.SHUT_WR)
                        self.assertEqual(recv_exact(control, 9), b"after FIN")
                        self.assert_closed(control)

    def test_slow_dns_respects_connection_deadline(self):
        with socket.socket() as listener, self.control() as control:
            listener.bind(("127.0.0.1", 0))
            listener.listen()
            control.settimeout(1.5)
            start = time.monotonic()
            control.sendall(b"\x05\x01\x00" +
                            encode_address("slow.test", listener.getsockname()[1], domain=True))
            header, _ = read_reply(control)
            self.assertEqual(header[:3], b"\x05\x04\x00")
            self.assertLess(time.monotonic() - start, 1.5)
            self.assert_closed(control)
            # Keep the listener open beyond the delayed resolver's completion.
            listener.settimeout(1.2)
            with self.assertRaises(socket.timeout):
                listener.accept()

    def test_slow_udp_dns_does_not_pin_client(self):
        with self.control() as control, \
             socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as rogue, \
             socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client, \
             socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as target:
            relay = self.associate(control)
            rogue.bind(("127.0.0.1", 0))
            client.bind(("127.0.0.1", 0))
            target.bind(("127.0.0.1", 0))
            target.settimeout(1.5)
            client.settimeout(2)
            rogue.sendto(b"\x00\x00\x00" +
                         encode_address("slow.test", target.getsockname()[1], domain=True) +
                         b"slow", relay)
            time.sleep(0.1)
            request = b"\x00\x00\x00" + encode_address(*target.getsockname()) + b"valid"
            client.sendto(request, relay)
            data, outbound = target.recvfrom(100)
            self.assertEqual(data, b"valid")
            target.sendto(data, outbound)
            self.assertEqual(client.recvfrom(100)[0], request)
            # A late resolver result must never deliver the timed-out datagram.
            target.settimeout(1.2)
            with self.assertRaises(socket.timeout):
                target.recvfrom(100)

    def test_udp_dns_wait_respects_remaining_idle_budget(self):
        with self.control() as control, \
             socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
            relay = self.associate(control)
            time.sleep(2.5)
            control.settimeout(0.8)
            client.sendto(b"\x00\x00\x00" + encode_address("slow.test", 12345, domain=True),
                          relay)
            self.assert_closed(control)


class IPv6ProxyTests(ProxyTestCase):
    listen_host = "::1"

    def test_ipv6_listener_large_udp(self):
        for family, host in ((socket.AF_INET, "127.0.0.1"), (socket.AF_INET6, "::1")):
            ProxyTests.large_udp_round_trip(self, family, host)

    def test_ipv6_listener_tcp(self):
        with socket.socket() as listener, self.control() as control:
            listener.bind(("127.0.0.1", 0))
            listener.listen()
            listener.settimeout(2)
            control.sendall(b"\x05\x01\x00" +
                            encode_address("127.0.0.1", listener.getsockname()[1]))
            self.assertEqual(read_reply(control)[0][:3], b"\x05\x00\x00")
            with listener.accept()[0] as target:
                target.settimeout(2)
                control.sendall(b"ipv6 listener")
                self.assertEqual(recv_exact(target, 13), b"ipv6 listener")
                target.sendall(b"reply")
                self.assertEqual(recv_exact(control, 5), b"reply")

    def test_ipv6_listener_udp(self):
        with self.control() as control, \
             socket.socket(socket.AF_INET6, socket.SOCK_DGRAM) as client, \
             socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as target:
            relay = self.associate(control)
            self.assertEqual(relay[0], "::1")
            target.bind(("127.0.0.1", 0))
            target.settimeout(2)
            client.settimeout(2)
            request = b"\x00\x00\x00" + encode_address(*target.getsockname()) + b"ipv6 client"
            client.sendto(request, relay)
            data, outbound = target.recvfrom(100)
            self.assertEqual(data, b"ipv6 client")
            target.sendto(data, outbound)
            self.assertEqual(client.recvfrom(100)[0], request)


class WildcardListenerTests(ProxyTestCase):
    listen_host = "0.0.0.0"
    client_host = "127.0.0.1"
    family = socket.AF_INET

    def test_listener_rejects_conflicting_binds(self):
        # Darwin permits same-account wildcard/specific overlap with REUSEADDR.
        # Check duplicate wildcard endpoints there; Windows and Linux also reject
        # competing specific endpoints. Keep the real relay check on every OS.
        hosts = (self.listen_host,) if sys.platform == "darwin" else (
            self.listen_host, self.client_host)
        for host in hosts:
            for reuse in (False, True):
                with self.subTest(host=host, reuse=reuse), socket.socket(self.family) as contender:
                    if reuse:
                        contender.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                    # Unix may allow bind with REUSEADDR, but must reject listen.
                    with self.assertRaises(OSError) as rejected:
                        contender.bind((host, self.port))
                        contender.listen()
                    self.assertIn(rejected.exception.errno,
                                  (errno.EADDRINUSE, errno.EACCES, 10048, 10013))

        # Failed competing binds must leave actual proxy traffic working.
        with socket.socket(self.family) as listener:
            listener.bind((self.client_host, 0))
            listener.listen()
            listener.settimeout(2)
            with socket.create_connection((self.client_host, self.port), 2) as control:
                control.settimeout(2)
                control.sendall(GREETING + b"\x05\x01\x00" +
                                encode_address(self.client_host, listener.getsockname()[1]) +
                                b"exclusive request")
                control.shutdown(socket.SHUT_WR)
                self.assertEqual(recv_exact(control, 2), b"\x05\x00")
                self.assertEqual(read_reply(control)[0][:3], b"\x05\x00\x00")
                with listener.accept()[0] as target:
                    target.settimeout(2)
                    self.assertEqual(recv_exact(target, 17), b"exclusive request")
                    self.assertEqual(target.recv(1), b"")
                    target.sendall(b"exclusive reply")
                    target.shutdown(socket.SHUT_WR)
                    self.assertEqual(recv_exact(control, 15), b"exclusive reply")
                    self.assertEqual(control.recv(1), b"")

    def test_existing_listener_prevents_wildcard_startup(self):
        self.check_existing_listener(self.listen_host)

    @unittest.skipIf(sys.platform == "darwin", "Darwin permits wildcard/specific port overlap")
    def test_existing_specific_listener_prevents_wildcard_startup(self):
        self.check_existing_listener(self.client_host)

    def check_existing_listener(self, bind_host):
        with socket.socket(self.family) as existing:
            existing.bind((bind_host, 0))
            existing.listen()
            result = subprocess.run(
                [str(BINARY), self.listen_host, str(existing.getsockname()[1])],
                capture_output=True, text=True, timeout=3)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("Could not listen", result.stderr)
            self.assertNotIn("SOCKS5 listening on", result.stderr)
            # The failed proxy must leave the first listener intact.
            existing.settimeout(2)
            with socket.create_connection((self.client_host, existing.getsockname()[1]), 2):
                with existing.accept()[0] as accepted:
                    self.assertEqual(accepted.getsockname()[1], existing.getsockname()[1])


class WildcardIPv6ListenerTests(WildcardListenerTests):
    listen_host = "::"
    client_host = "::1"
    family = socket.AF_INET6


@unittest.skipUnless(sys.platform == "win32", "requires Windows exclusive UDP binding")
class WindowsUDPBindingTests(ProxyTestCase):
    def check_competing_udp_binds(self, family, endpoint, include_wildcard=True):
        wildcard = "::" if family == socket.AF_INET6 else "0.0.0.0"
        hosts = (wildcard, endpoint[0]) if include_wildcard else (endpoint[0],)
        for host in hosts:
            for reuse in (False, True):
                with self.subTest(host=host, reuse=reuse), \
                     socket.socket(family, socket.SOCK_DGRAM) as contender:
                    if reuse:
                        contender.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                    with self.assertRaises(OSError) as rejected:
                        contender.bind((host, endpoint[1]))
                    self.assertIn(rejected.exception.errno, (errno.EACCES, errno.EADDRINUSE,
                                                            10013, 10048))

    def check_outbound_binding(self, family, host):
        with self.control() as control, \
             socket.socket(family, socket.SOCK_DGRAM) as target, \
             socket.socket(socket.AF_INET6 if ":" in self.listen_host else socket.AF_INET,
                           socket.SOCK_DGRAM) as client:
            try:
                target.bind((host, 0))
            except OSError:
                if family == socket.AF_INET6:
                    self.skipTest("IPv6 loopback is unavailable")
                raise
            target.settimeout(2)
            client.settimeout(2)
            relay = self.associate(control)
            header = bytes(3) + encode_address(host, target.getsockname()[1])
            client.sendto(header + b"request", relay)
            payload, outbound = target.recvfrom(100)
            self.assertEqual(payload, b"request")
            self.check_competing_udp_binds(family, outbound)
            for payload in (b"", b"reply after competing binds"):
                target.sendto(payload, outbound)
                self.assertEqual(client.recvfrom(100)[0], header + payload)
            client.sendto(header + b"next request", relay)
            self.assertEqual(target.recvfrom(100), (b"next request", outbound))

    def test_ipv4_udp_outbound_is_exclusive(self):
        self.check_outbound_binding(socket.AF_INET, "127.0.0.1")

    def test_ipv6_udp_outbound_is_exclusive(self):
        self.check_outbound_binding(socket.AF_INET6, "::1")

    def test_udp_association_is_exclusive(self):
        family = socket.AF_INET6 if ":" in self.listen_host else socket.AF_INET
        with self.control() as control, \
             socket.socket(family, socket.SOCK_DGRAM) as client, \
             socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as target:
            relay = self.associate(control)
            self.check_competing_udp_binds(family, relay, include_wildcard=False)
            target.bind(("127.0.0.1", 0))
            target.settimeout(2)
            client.settimeout(2)
            wildcard = "::" if family == socket.AF_INET6 else "0.0.0.0"
            for reuse in (False, True):
                # A wildcard bind may cover other interfaces; it must not steal
                # traffic from the association's exclusive concrete endpoint.
                with self.subTest(reuse=reuse), socket.socket(family, socket.SOCK_DGRAM) as contender:
                    if reuse:
                        contender.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                    bound = False
                    try:
                        contender.bind((wildcard, relay[1]))
                        bound = True
                    except OSError as rejected:
                        self.assertIn(rejected.errno, (errno.EACCES, errno.EADDRINUSE, 10013, 10048))
                    payload = b"association" + bytes([reuse])
                    request = bytes(3) + encode_address(*target.getsockname()) + payload
                    client.sendto(request, relay)
                    readable = [target, contender] if bound else [target]
                    ready = select.select(readable, [], [], 2)[0]
                    self.assertIn(target, ready)
                    if bound:
                        self.assertNotIn(contender, ready)
                    echoed, outbound = target.recvfrom(100)
                    self.assertEqual(echoed, payload)
                    target.sendto(payload, outbound)
                    self.assertEqual(client.recvfrom(100)[0], request)


class WindowsUDPIPv6BindingTests(WindowsUDPBindingTests):
    listen_host = "::1"


if __name__ == "__main__":
    unittest.main()
