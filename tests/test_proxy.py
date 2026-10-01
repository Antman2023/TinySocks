"""End-to-end checks for a build with limits of 2 clients, 1s handshake, 3s idle."""

import socket
import struct
import subprocess
import sys
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
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

    def test_authentication_rejection(self):
        with socket.create_connection(("127.0.0.1", self.port), 2) as control:
            control.sendall(b"\x05\x01\x02")
            self.assertEqual(recv_exact(control, 2), b"\x05\xff")
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

    def test_tcp_large_payload_drains_before_half_close(self):
        payload = bytes(range(256)) * 4096
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
            rogue.sendto(b"invalid", relay)
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
