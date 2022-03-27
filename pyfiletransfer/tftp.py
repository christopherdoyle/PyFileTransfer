"""THE TFTP PROTOCOL (REVISION 2).

Ref: https://datatracker.ietf.org/doc/html/rfc1350/

* netascii: 8 bit ascii
* octet: 8 bit bytes
* mail: netascii sent to a user rather than a file (obsoleted)

"""
from __future__ import annotations

import socket
import struct
from abc import ABC, abstractmethod
from enum import Enum
from random import SystemRandom
from typing import Dict, Type, Optional

BLOCK_SIZE_BYTES = 512
SYSTEM_RANDOM = SystemRandom()

# RFC 764
NUL = b"\x00"
LF = b"\x0A"
CR = b"\x0D"
BELL = b"\x07"
BS = b"\x08"
HT = b"\x09"
VT = b"\x0B"
FF = b"\x0C"


def netascii_encode(s: str) -> bytes:
    result = bytes(ord(c) for c in s)
    # TODO CRLF, NUL
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
        _IPACKET_REGISTRY[PacketType.value] = cls

    @abstractmethod
    def from_data(self, data: bytes) -> IPacket:
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

    def data(self) -> bytes:
        """Encodes the package into a sendable request. The encoding is always in
        netascii.
        """
        opcode = self.package_type.value
        filename = netascii_encode(self.filename)
        mode = netascii_encode(self.mode.value)
        structure = self.structure.format(
            filename_size=len(filename), mode_size=len(mode)
        )
        return struct.pack(structure, opcode, filename, NUL, mode, NUL)


class WriteRequestPacket(ReadRequestPacket):
    package_type: PacketType = PacketType.WRITE_REQUEST


class DataPacket(IPacket):
    package_type: PacketType = PacketType.ACKNOWLEDGEMENT

    def __init__(
        self,
        block_number: int,
        data: bytes,
    ) -> None:
        self.block_number = block_number
        self.data = data

        if self.block_number <= 0:
            raise ValueError("block_number must be >= 1")

        if len(self.data) >= 512:
            raise ValueError("data must be less than 512 bytes")


class AckPacket(IPacket):
    package_type: PacketType = PacketType.ACKNOWLEDGEMENT

    def __init__(self, block_number: int) -> None:
        self.block_number = block_number
        if self.block_number <= 0:
            raise ValueError("block_number must be >= 1")


class ErrorPacket(IPacket):
    def __init__(self, error_code: int, error_message: str) -> None:
        self.error_code = error_code
        self.error_message = error_message


class TransferIdentifier:
    MIN = 0
    MAX = 65535

    def __init__(self, tid: int = None) -> None:
        if tid is None:
            self.tid = self.random_tid()
        else:
            self.tid = tid

    def random_tid(self) -> int:
        return SYSTEM_RANDOM.randint(self.MIN, self.MAX)


SERVER_TID = TransferIdentifier(69)


def read_packet(packet: bytes) -> IPacket:
    opcode_bytes = packet[:2]
    opcode_int = int.from_bytes(opcode_bytes, "big")
    package_type = PacketType(opcode_int)
    package_class = package_type.implementation
    if package_class is None:
        raise ValueError(f"No implementation found for {package_type}")

    instance = package_class.from_data(packet)
    return instance


def read_file(target_ip):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_address = target_ip
    server_tid = SERVER_TID
    source_tid = TransferIdentifier()
    sock.bind(("0.0.0.0", source_tid.tid))
    rrq = ReadRequestPacket(filename="file.txt", mode=TransferMode.NETASCII)
    sock.sendto(rrq.data(), (server_address, server_tid.tid))
