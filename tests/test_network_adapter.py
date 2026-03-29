from __future__ import annotations

import socket
import threading
import time
import unittest

from bkzs_guard.adapters.network import UdpTcpAdapter


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


class NetworkAdapterTests(unittest.TestCase):
    def test_udp_adapter_receives_remote_payload(self) -> None:
        port = _free_port()
        adapter = UdpTcpAdapter(protocol="udp", host="127.0.0.1", port=port, timeout_seconds=1.0)
        adapter.connect()

        def sender() -> None:
            time.sleep(0.1)
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.sendto(b"udp-probe", ("127.0.0.1", port))

        thread = threading.Thread(target=sender, daemon=True)
        thread.start()
        packets = adapter.listen_batch(max_packets=1)
        adapter.close()

        self.assertEqual(packets, ["udp-probe"])

    def test_tcp_adapter_receives_remote_payload(self) -> None:
        port = _free_port()
        adapter = UdpTcpAdapter(protocol="tcp", host="127.0.0.1", port=port, timeout_seconds=1.0)
        adapter.connect()

        def sender() -> None:
            time.sleep(0.1)
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.connect(("127.0.0.1", port))
                sock.sendall(b"tcp-probe")

        thread = threading.Thread(target=sender, daemon=True)
        thread.start()
        packets = adapter.listen_batch(max_packets=1)
        adapter.close()

        self.assertEqual(packets, ["tcp-probe"])


if __name__ == "__main__":
    unittest.main()
