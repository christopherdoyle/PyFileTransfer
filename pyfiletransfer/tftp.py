"""THE TFTP PROTOCOL (REVISION 2).

Ref: https://datatracker.ietf.org/doc/html/rfc1350/

* netascii: 8 bit ascii
* octet: 8 bit bytes
* mail: netascii sent to a user rather than a file (obsoleted)

"""
from __future__ import annotations

import io
import logging
import pathlib
import socket
import struct
import time
from abc import ABC, abstractmethod
from enum import Enum
from random import SystemRandom
from typing import Dict, Type, Optional, Union

from .lib.nt import ctrl_cancel_async_io
from .logging import UserLogger

SYSTEM_RANDOM = SystemRandom()
PATHLIKE = Union[str, pathlib.Path]
logger = logging.getLogger(__name__)

# RFC 764
NUL = b"\x00"
LF = b"\x0A"
CR = b"\x0D"
BELL = b"\x07"
BS = b"\x08"
HT = b"\x09"
VT = b"\x0B"
FF = b"\x0C"


def encode_netascii(s: str) -> bytes:
    result = bytes(ord(c) for c in s)
    # TODO CRLF, NUL
    return result


def decode_netascii(data: bytes) -> str:
    result = "".join(chr(c) for c in data)
    return result


class ErrorCodes(Enum):
    NOT_DEFINED = 0
    FILE_NOT_FOUND = 1
    ACCESS_VIOLATION = 2
    DISK_FULL_OR_ALLOCATION_EXCEEDED = 3
    ILLEGAL_TFTP_OPERATION = 4
    UNKNOWN_TRANSFER_ID = 5
    FILE_ALREADY_EXISTS = 6
    NO_SUCH_USER = 7


class TransferMode(Enum):
    NETASCII = "netascii"
    OCTET = "octet"
    MAIL = "mail"


class PacketType(Enum):
    READ_REQUEST = 1
    WRITE_REQUEST = 2
    DATA = 3
    ACKNOWLEDGEMENT = 4
    ERROR = 5

    @property
    def implementation(self) -> Optional[IPacket]:
        return _IPACKET_REGISTRY.get(self.value)


_IPACKET_REGISTRY: Dict[int, Type[IPacket]] = {}


class IPacket(ABC):
    """See Section 5 of RFC 1350."""

    package_type: NotImplemented

    def __init_subclass__(cls, **__) -> None:
        if cls.package_type in _IPACKET_REGISTRY:
            raise ValueError(
                f"Implementation for PackageType {cls.package_type} already exists"
            )
        _IPACKET_REGISTRY[cls.package_type.value] = cls

    def __str__(self) -> str:
        if self.__dict__:
            description = " | ".join(f"{k}={v}" for k, v in self.__dict__.items())
        else:
            description = f" at {id(self):#x}"
        return f"<{self.__class__.__name__} {description}>"

    @abstractmethod
    def data(self) -> bytes:
        """Serialize the instance to bytes matching the packet format."""

    @classmethod
    @abstractmethod
    def from_data(cls, data: bytes) -> IPacket:
        """Deserialize the instance from bytes."""


class TfptException(Exception):
    pass


class ProtocolException(TfptException):
    pass


class PacketReadException(TfptException):
    pass


class ReadRequestPacket(IPacket):
    """
           2 bytes    string    1 byte    string    1 byte
          -------------------------------------------------
    RRQ   | 01/02 |  Filename  |   0  |    Mode    |   0  |
          -------------------------------------------------
    """

    package_type: PacketType = PacketType.READ_REQUEST

    # ! = network (big-endian)
    structure = "!h{filename_size:d}sc{mode_size:d}sc"

    def __init__(
        self,
        filename: str,
        mode: TransferMode,
    ) -> None:
        self.filename = filename
        self.mode = mode

    @classmethod
    def from_data(cls, data: bytes) -> ReadRequestPacket:
        remainder = data[2:]
        null_terminator_index = remainder.index(b"\x00")
        if null_terminator_index < 0:
            raise PacketReadException("Packet does not meet expected format")
        filename_block = remainder[:null_terminator_index]

        remainder = remainder[null_terminator_index + 1 :]
        null_terminator_index = remainder.index(b"\x00")
        if null_terminator_index < 0:
            raise PacketReadException("Packet does not meet expected format")

        mode_block = remainder[:null_terminator_index]

        if len(remainder[null_terminator_index:]) > 1:
            raise PacketReadException("Packet does not meet expected format")

        packet = ReadRequestPacket(
            decode_netascii(filename_block),
            TransferMode[decode_netascii(mode_block).upper()],
        )
        return packet

    def data(self) -> bytes:
        """Encodes the package into a sendable request. The encoding is always in
        netascii.
        """
        opcode = self.package_type.value
        filename = encode_netascii(self.filename)
        mode = encode_netascii(self.mode.value)
        structure = self.structure.format(
            filename_size=len(filename), mode_size=len(mode)
        )
        return struct.pack(structure, opcode, filename, NUL, mode, NUL)


class WriteRequestPacket(ReadRequestPacket):
    package_type: PacketType = PacketType.WRITE_REQUEST


class DataPacket(IPacket):
    """
     2 bytes     2 bytes      n bytes
     ----------------------------------
    | Opcode |   Block #  |   Data     |
     ----------------------------------
    """

    package_type: PacketType = PacketType.DATA
    max_block_size = 512

    def __init__(
        self,
        block_number: int,
        data: bytes,
    ) -> None:
        self.block_number = block_number
        self.raw_data = data

        if self.block_number <= 0:
            raise ValueError("block_number must be >= 1")

        if len(self.raw_data) > self.max_block_size:
            raise ValueError("data must be less than 512 bytes")

    @property
    def end_of_data(self) -> bool:
        return len(self.raw_data) < self.max_block_size

    def data(self) -> bytes:
        result = struct.pack("!hh", self.package_type.value, self.block_number)
        result += self.raw_data
        return result

    @classmethod
    def from_data(cls, data: bytes) -> DataPacket:
        if len(data) < 4:
            raise PacketReadException("Unexpected packet length (packet too small)")
        block_number = int.from_bytes(data[2:4], byteorder="big")
        data = data[4:]
        instance = DataPacket(block_number, data)
        return instance


class AckPacket(IPacket):
    """
      2 bytes     2 bytes
     ---------------------
    | Opcode |   Block #  |
     ---------------------
    """

    package_type: PacketType = PacketType.ACKNOWLEDGEMENT

    def __init__(self, block_number: int) -> None:
        self.block_number = block_number
        if self.block_number <= 0:
            raise ValueError("block_number must be >= 1")

    @classmethod
    def from_data(cls, data: bytes) -> AckPacket:
        if len(data) != 4:
            raise PacketReadException("Unexpected packet length")
        block_number = int.from_bytes(data[2:], byteorder="big")
        instance = AckPacket(block_number)
        return instance

    def data(self) -> bytes:
        result = struct.pack("!hh", self.package_type.value, self.block_number)
        return result


class ErrorPacket(IPacket):
    """
     2 bytes     2 bytes      string    1 byte
     -----------------------------------------
    | Opcode |  ErrorCode |   ErrMsg   |   0  |
     -----------------------------------------
    """

    package_type = PacketType.ERROR
    structure = "!hh{error_message_size:d}sc"

    def __init__(self, error_code: int, error_message: str) -> None:
        self.error_code = error_code
        self.error_message = error_message

        try:
            self.error = ErrorCodes(self.error_code)
        except ValueError:
            self.error = None

    def data(self) -> bytes:
        opcode = self.package_type.value
        error_message = encode_netascii(self.error_message)
        structure = self.structure.format(error_message_size=len(error_message))
        return struct.pack(structure, opcode, self.error_code, error_message, NUL)

    @classmethod
    def from_data(cls, data: bytes) -> ErrorPacket:
        if data[-1:] != b"\x00":
            raise PacketReadException("Data packet is not terminated with null byte")
        opcode, error_code = struct.unpack("!hh", data[:4])
        # error_code = int.from_bytes(data[2:4], byteorder="big")
        error_message = decode_netascii(data[4:-1])
        instance = ErrorPacket(error_code, error_message)
        return instance


class TransferIdentifier:
    MIN = 0
    USER_MIN = 1024
    MAX = 65535

    def __init__(self, tid: int = None, user_level: bool = True) -> None:
        self.user_level = user_level
        if tid is None:
            self.tid = self.random_tid()
        else:
            self.tid = tid

    def random_tid(self) -> int:
        return SYSTEM_RANDOM.randint(
            self.USER_MIN if self.user_level else self.MIN, self.MAX
        )


SERVER_TID = TransferIdentifier(69)


class TftpPacketClient:
    def __init__(self, server_ip: str) -> None:
        # TODO mixin logger w/ classname & connection details
        self.server_ip = server_ip
        self.sock: socket.socket = None
        self.server_tid: TransferIdentifier = None

    def connect(self) -> None:
        logger.info("Initializing socket")
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("0.0.0.0", 0))
        logger.info("Client TID = %d", self.sock.getsockname()[1])

    def close(self) -> None:
        self.sock.close()

    def receive(self) -> IPacket:
        # TODO ctrl-c on Windows still iffy
        while True:
            with ctrl_cancel_async_io(self.sock.fileno()):
                try:
                    # the Tftp spec implies Datagrab length < 516
                    data, (sender_ip, sender_port) = self.sock.recvfrom(516)
                    logger.debug("Received data from %s:%d", sender_ip, sender_port)

                    if (sender_ip == self.server_ip) and (
                        self.server_tid is None or self.server_tid.tid == sender_port
                    ):
                        break
                except KeyboardInterrupt:
                    logger.error("Keyboard interrupt detected, exiting")
                    raise

        if self.server_tid is None:
            self.server_tid = TransferIdentifier(sender_port)

        logger.info("Processing server response")
        packet = self.read_packet(data)
        return packet

    def send(self, packet: IPacket) -> None:
        self.sock.sendto(
            packet.data(), (self.server_ip, (self.server_tid or SERVER_TID).tid)
        )

    @staticmethod
    def read_packet(packet: bytes) -> IPacket:
        opcode_bytes = packet[:2]
        opcode_int = int.from_bytes(opcode_bytes, "big")
        package_type = PacketType(opcode_int)
        package_class = package_type.implementation
        if package_class is None:
            raise ValueError(f"No implementation found for {package_type}")

        instance = package_class.from_data(packet)
        return instance


class TftpClient:
    def __init__(self, server_ip: str) -> None:
        self.packet_client = TftpPacketClient(server_ip)

    def download_file(
        self,
        remote_filename: str,
        local_filepath: PATHLIKE,
        mode: TransferMode = TransferMode.NETASCII,
    ) -> None:
        raise NotImplementedError

    def read_file(
        self, remote_filename: str, mode: TransferMode = TransferMode.NETASCII
    ) -> io.StringIO:
        response_stream = io.StringIO()

        self.packet_client.connect()
        rrq = ReadRequestPacket(filename=remote_filename, mode=mode)
        self.packet_client.send(rrq)

        block_number = 1

        while True:
            packet = self.packet_client.receive()
            packet = self._check_data_packet(packet, block_number)
            if packet is None:
                continue

            response_stream.write(decode_netascii(packet.raw_data))
            logger.debug("Sending ACK")
            self.packet_client.send(AckPacket(packet.block_number))

            if packet.end_of_data:
                # dallying is encouraged
                logger.info("End Of Data detected, closing socket after 1 second")
                time.sleep(1)
                self.packet_client.close()
                break

            block_number += 1

        logger.info("Read file complete")

        response_stream.seek(0)
        return response_stream

    def upload_file(
        self,
        remote_filename: str,
        local_filepath: PATHLIKE,
        mode: TransferMode = TransferMode.NETASCII,
    ) -> None:
        raise NotImplementedError

    def write_file(
        self,
        remote_filename: str,
        data: Union[str, io.StringIO],
        mode: TransferMode = TransferMode.NETASCII,
    ) -> None:
        raise NotImplementedError

    @staticmethod
    def _check_data_packet(packet: IPacket, block_number: int) -> DataPacket:
        if not isinstance(packet, DataPacket):
            raise ProtocolException(
                f"Expected {DataPacket.package_type.name}, "
                f"got {packet.package_type.name}"
            )

        if packet.block_number < block_number:
            logger.warning(
                f"Expected block_number={block_number}, "
                f"got block_number={packet.block_number}, probably dupe"
            )
        elif packet.block_number > block_number:
            raise ProtocolException(
                f"Expected block_number={block_number}, "
                f"got block_number={packet.block_number}, packet loss detected"
            )

        return packet


def main():
    UserLogger().add_stderr(logging.DEBUG)
    print(TftpClient("127.0.0.1").read_file("file.txt").read())


if __name__ == "__main__":
    main()
