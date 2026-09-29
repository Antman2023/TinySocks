"""End-to-end checks for a build with limits of 2 clients, 1s handshake, 3s idle."""

import socket
import struct
import subprocess
import sys
import time
import unittest
from pathlib import Path


BINARY = Path(sys.argv.pop(1)).resolve()
GREETING = b"\x05\x01\x00"


def recv_exact(sock, length):
    data = bytearray()
    while len(data) < length:
        chunk = sock.recv(length - len(data))
        if not chunk:
            raise EOFError("connection closed")
        data.extend(chunk)
    return bytes(data)


class ProxyTests(unittest.TestCase):
    def setUp(self):
        reservation = socket.socket()
        reservation.bind(("127.0.0.1", 0))
        self.port = reservation.getsockname()[1]
        reservation.close()
        self.proxy = subprocess.Popen(
            [str(BINARY), "127.0.0.1", str(self.port)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline:
            if self.proxy.poll() is not None:
                self.fail("proxy exited before listening")
            try:
                probe = socket.create_connection(("127.0.0.1", self.port), 0.1)
                probe.close()
                break
            except OSError:
                time.sleep(0.02)
        else:
            self.fail("proxy did not start")
        time.sleep(0.05)

    def tearDown(self):
        self.proxy.terminate()
        self.proxy.wait(timeout=3)

    def control(self):
        sock = socket.create_connection(("127.0.0.1", self.port), 2)
        sock.settimeout(5)
        sock.sendall(GREETING)
        self.assertEqual(recv_exact(sock, 2), b"\x05\x00")
        return sock

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


if __name__ == "__main__":
    unittest.main()
