"""Capture an emulated release's syscalls when its domain protocol checks fail."""

import re
import socket
import struct
import subprocess
import sys
import tempfile
import time
from pathlib import Path


binary, runner = Path(sys.argv[1]).resolve(), sys.argv[2]
with tempfile.TemporaryDirectory(prefix="tinysocks-trace-") as temporary, socket.socket() as target:
    target.bind(("127.0.0.1", 0))
    target.listen()
    trace_path = Path(temporary) / "syscalls.log"
    with trace_path.open("w", encoding="utf-8") as trace:
        proxy = subprocess.Popen([runner, "-strace", str(binary), "127.0.0.1", "0"],
                                 stdout=subprocess.DEVNULL, stderr=trace)
        try:
            deadline = time.monotonic() + 3
            while True:
                output = trace_path.read_text(encoding="utf-8", errors="replace")
                listening = re.search(r"SOCKS5 listening on 127\.0\.0\.1:(\d+)", output)
                if listening:
                    break
                if proxy.poll() is not None or time.monotonic() >= deadline:
                    raise RuntimeError("traced release did not start")
                time.sleep(0.01)
            with socket.create_connection(("127.0.0.1", int(listening[1])), 2) as control:
                control.settimeout(3)
                request = (b"\x05\x01\x00\x05\x01\x00\x03\x09localhost" +
                           struct.pack("!H", target.getsockname()[1]))
                control.sendall(request)
                reply = bytearray()
                while len(reply) < 12:
                    part = control.recv(12 - len(reply))
                    if not part:
                        break
                    reply.extend(part)
                print(f"Traced localhost CONNECT reply: {reply.hex()}", flush=True)
        finally:
            if proxy.poll() is None:
                proxy.terminate()
            proxy.wait(timeout=3)
            trace.flush()
            print(trace_path.read_text(encoding="utf-8", errors="replace"), flush=True)
