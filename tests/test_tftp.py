from __future__ import annotations
import socket
import threading
from enum import Enum
from pathlib import Path
from queue import Queue
from typing import Type

import pytest

from pyfiletransfer import tftp


class MockPacketType(Enum):
    MOCK = 9

    @property
    def implementation(self) -> Type[MockPacket]:
        return MockPacket


class MockPacket(tftp.IPacket):

    packet_type = MockPacketType.MOCK

    def __init__(self, data: bytes) -> None:
        self._data = data

    def data(self) -> bytes:
        return self._data

    @classmethod
    def from_data(cls, data: bytes) -> MockPacket:
        return MockPacket(data)


class TestReadRequestPacket:
    def test_data(self) -> None:
        p = tftp.ReadRequestPacket(filename="HELLO", mode=tftp.TransferMode.NETASCII)
        expected = (
            # 01
            b"\x00\x01"
            # HELLO
            b"\x48\x45\x4C\x4C\x4F"
            # 0
            b"\x00"
            # netascii
            b"\x6e\x65\x74\x61\x73\x63\x69\x69"
            # 0
            b"\x00"
        )
        result = p.data()
        assert result == expected

    def test_from_data(self) -> None:
        data = (
            # opcode
            b"\x00\x01"
            # filename
            b"HelloWorld.txt\x00"
            # mode
            b"netascii\x00"
        )
        expected = tftp.ReadRequestPacket(
            filename="HelloWorld.txt", mode=tftp.TransferMode.NETASCII
        )
        actual = tftp.ReadRequestPacket.from_data(data)
        assert expected.filename == actual.filename
        assert expected.mode == actual.mode


class TestDataPacket:
    @pytest.mark.parametrize("n_bytes", (0, 1, 511))
    def test_less_than_512_bytes__is_end_of_data(self, n_bytes: int) -> None:
        data = b"\x01" * n_bytes
        instance = tftp.DataPacket(1, data)
        assert instance.end_of_data

    def test_512_bytes__is_not_end_of_data(self) -> None:
        data = b"\x01" * 512
        instance = tftp.DataPacket(1, data)
        assert not instance.end_of_data

    def test_init_greater_than_512_bytes__raises(self) -> None:
        data = b"\x01" * 513
        with pytest.raises(ValueError, match=r".*512.*"):
            tftp.DataPacket(1, data)

    def test_from_data(self) -> None:
        data = (
            # opcode
            b"\x00\x03"
            # block number
            b"\x00\x0A"
            # data
            b"\x00\x01\x02"
        )
        expected = tftp.DataPacket(
            block_number=10,
            data=b"\x00\x01\x02",
        )
        actual = tftp.DataPacket.from_data(data)
        assert expected.block_number == actual.block_number
        assert expected.raw_data == actual.raw_data

    def test_data(self) -> None:
        expected = (
            # opcode
            b"\x00\x03"
            # block number
            b"\x00\x0A"
            # data
            b"\x00\x01\x02"
        )
        instance = tftp.DataPacket(
            block_number=10,
            data=b"\x00\x01\x02",
        )
        actual = instance.data()
        assert expected == actual


class TestAckPacket:
    def test_data(self) -> None:
        expected = b"\x00\x04\x00\x11"
        instance = tftp.AckPacket(17)
        actual = instance.data()
        assert expected == actual

    def test_from_data(self) -> None:
        data = b"\x00\x04\x00\x11"
        expected = tftp.AckPacket(17)
        actual = tftp.AckPacket.from_data(data)
        assert expected.block_number == actual.block_number


class TestErrorPacket:
    def test_error_enum_is_mapped(self) -> None:
        instance = tftp.ErrorPacket(1, "")
        assert instance.error is tftp.ErrorCodes.FILE_NOT_FOUND

    def test_data(self) -> None:
        expected = (
            # opcode
            b"\x00\x05"
            # error code - Unknown transfer ID
            b"\x00\x05"
            # error message
            b"You plonker\x00"
        )
        instance = tftp.ErrorPacket(5, "You plonker")
        actual = instance.data()
        assert expected == actual

    def test_from_data(self) -> None:
        data = (
            # opcode
            b"\x00\x05"
            # error code - Unknown transfer ID
            b"\x00\x05"
            # error message
            b"You plonker\x00"
        )
        expected = tftp.ErrorPacket(5, "You plonker")
        actual = tftp.ErrorPacket.from_data(data)
        assert expected.error_code == actual.error_code
        assert expected.error_message == actual.error_message
        assert expected.error == actual.error


class TestTftpPacketClient:
    def test_send(self) -> None:
        packet = MockPacket(b"HOT BUTTER")
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(("0.0.0.0", 0))
        server_port = int(sock.getsockname()[1])
        result_queue = Queue()

        def server(sock: socket.socket, result: Queue) -> None:
            sock.settimeout(1)
            message, remote = sock.recvfrom(1024)
            result.put((message, remote))

        server_thread = threading.Thread(
            target=server, kwargs=dict(sock=sock, result=result_queue)
        )
        server_thread.start()

        client = tftp.TftpPacketClient(server_ip="127.0.0.1", server_port=server_port)
        client.connect()
        client.send(packet)

        server_thread.join()

        result = result_queue.get(block=False, timeout=0)
        assert result is not None
        assert result[0] == b"HOT BUTTER"
        assert result[1] == ("127.0.0.1", client.client_port)


class TestClientServerIntegration:
    def test(self) -> None:
        expected = "Hello World"
        test_filepath = Path("test.txt")
        test_filepath.unlink(missing_ok=True)

        server = tftp.TftpServer("127.0.0.1", 0)
        server_thread = threading.Thread(
            target=server.serve_forever, name="Thread-Server"
        )
        server_thread.daemon = True
        server_thread.start()

        client = tftp.TftpClient(*server.socket.getsockname())
        client_thread = threading.Thread(
            target=client.write_file,
            kwargs=dict(remote_filename=str(test_filepath), data=expected),
            name="Thread-Client",
        )
        client_thread.daemon = True
        client_thread.start()

        client_thread.join()
        server.shutdown()
        server_thread.join()

        actual = test_filepath.read_text()
        assert expected == actual
