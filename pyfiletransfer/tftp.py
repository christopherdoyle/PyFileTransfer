"""THE TFTP PROTOCOL (REVISION 2).

Ref: https://datatracker.ietf.org/doc/html/rfc1350/

* netascii: 8 bit ascii
* octet: 8 bit bytes
* mail: netascii sent to a user rather than a file (obsoleted)

"""
from __future__ import annotations

import io
import logging
import socket
import socketserver
import struct
import sys
import time
from abc import ABC, abstractmethod
from enum import Enum
from functools import partial
from pathlib import Path
from typing import Dict, Type, Optional, Union, Iterator, Tuple

from .util.func import identity
from .util.logging import UserLogger
from .util.io import PathLike, to_path, user_data_directory
from .util.nt import ctrl_cancel_async_io

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

    packet_type: NotImplemented

    def __init_subclass__(cls, **__) -> None:
        if cls.packet_type in _IPACKET_REGISTRY:
            raise ValueError(
                f"Implementation for PackageType {cls.packet_type} already exists"
            )
        _IPACKET_REGISTRY[cls.packet_type.value] = cls

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

    packet_type: PacketType = PacketType.READ_REQUEST

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
        opcode = self.packet_type.value
        filename = encode_netascii(self.filename)
        mode = encode_netascii(self.mode.value)
        structure = self.structure.format(
            filename_size=len(filename), mode_size=len(mode)
        )
        return struct.pack(structure, opcode, filename, NUL, mode, NUL)


class WriteRequestPacket(ReadRequestPacket):
    packet_type: PacketType = PacketType.WRITE_REQUEST

    @classmethod
    def from_data(cls, data: bytes) -> WriteRequestPacket:
        rrq = super().from_data(data)
        wrq = WriteRequestPacket(filename=rrq.filename, mode=rrq.mode)
        return wrq


class DataPacket(IPacket):
    """
     2 bytes     2 bytes      n bytes
     ----------------------------------
    | Opcode |   Block #  |   Data     |
     ----------------------------------
    """

    packet_type: PacketType = PacketType.DATA
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
        result = struct.pack("!hh", self.packet_type.value, self.block_number)
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

    packet_type: PacketType = PacketType.ACKNOWLEDGEMENT

    def __init__(self, block_number: int) -> None:
        self.block_number = block_number
        if self.block_number < 0:
            raise ValueError("block_number must be >= 0")

    @classmethod
    def from_data(cls, data: bytes) -> AckPacket:
        if len(data) != 4:
            raise PacketReadException("Unexpected packet length")
        block_number = int.from_bytes(data[2:], byteorder="big")
        instance = AckPacket(block_number)
        return instance

    def data(self) -> bytes:
        result = struct.pack("!hh", self.packet_type.value, self.block_number)
        return result


class ErrorPacket(IPacket):
    """
     2 bytes     2 bytes      string    1 byte
     -----------------------------------------
    | Opcode |  ErrorCode |   ErrMsg   |   0  |
     -----------------------------------------
    """

    packet_type = PacketType.ERROR
    structure = "!hh{error_message_size:d}sc"

    def __init__(self, error_code: int, error_message: str) -> None:
        self.error_code = error_code
        self.error_message = error_message

        try:
            self.error = ErrorCodes(self.error_code)
        except ValueError:
            self.error = None

    def data(self) -> bytes:
        opcode = self.packet_type.value
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


class TftpPacketClient:
    def __init__(self, server_ip: str, server_port: int = 69) -> None:
        # TODO mixin logger w/ classname & connection details
        self.server_ip = server_ip
        self.sock: socket.socket = None
        self.initial_server_port: int = server_port
        self.server_port: int = None
        self.client_port: int = None

    def connect(self) -> None:
        logger.info("Initializing socket")
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("0.0.0.0", 0))
        self.client_port: int = self.sock.getsockname()[1]
        logger.info("Client TID = %d", self.client_port)

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

                    if sender_ip == self.server_ip:
                        if self.server_port is None:
                            self.server_port = sender_port
                            break
                        elif self.server_port == sender_port:
                            break

                except KeyboardInterrupt:
                    logger.error("Keyboard interrupt detected, exiting")
                    raise

        logger.info("Processing server response")
        packet = self.read_packet(data)
        return packet

    def send(self, packet: IPacket) -> None:
        self.sock.sendto(
            packet.data(),
            (self.server_ip, (self.server_port or self.initial_server_port)),
        )

    @staticmethod
    def read_packet(packet: bytes) -> IPacket:
        opcode_bytes = packet[:2]
        opcode_int = int.from_bytes(opcode_bytes, "big")
        packet_type = PacketType(opcode_int)
        package_class = packet_type.implementation
        if package_class is None:
            raise ValueError(f"No implementation found for {packet_type}")

        instance = package_class.from_data(packet)
        return instance


class TftpClient:
    def __init__(self, server_ip: str, server_port: int = 69) -> None:
        self.packet_client = TftpPacketClient(server_ip, server_port)

    def download_file(
        self,
        remote_filename: str,
        local_filepath: PathLike,
        mode: TransferMode = TransferMode.NETASCII,
        overwrite: bool = False,
    ) -> None:
        if mode is TransferMode.NETASCII:
            file_mode = "t"
            decode = decode_netascii
        elif mode is TransferMode.OCTET:
            file_mode = "b"
            decode = identity
        else:
            raise ValueError(
                "TransferMode for read requests must be NETASCII or OCTET; "
                "MAIL mode is only supported for write requests."
            )

        local_filepath = to_path(local_filepath)

        if overwrite:
            file_mode = "w" + file_mode
        else:
            # raises is file already exists, this is better than checking file
            # existence then opening with W b/c race conditions
            file_mode = "x" + file_mode

        fh = None
        try:
            fh = local_filepath.open(mode=file_mode)
            for packet in self._read(remote_filename=str(remote_filename), mode=mode):
                fh.write(decode(packet.raw_data))
        finally:
            if fh is not None:
                fh.close()

    def read_file(
        self, remote_filename: str, mode: TransferMode = TransferMode.NETASCII
    ) -> io.IOBase:
        if mode is TransferMode.NETASCII:
            response_stream = io.StringIO()
            decode = decode_netascii
        elif mode is TransferMode.OCTET:
            response_stream = io.BytesIO()
            decode = identity
        else:
            raise ValueError(
                "TransferMode for read requests must be NETASCII or OCTET; "
                "MAIL mode is only supported for write requests."
            )

        for packet in self._read(remote_filename=remote_filename, mode=mode):
            response_stream.write(decode(packet.raw_data))
        response_stream.seek(0)
        return response_stream

    def upload_file(
        self,
        remote_filename: str,
        local_filepath: PathLike,
        mode: TransferMode = TransferMode.NETASCII,
    ) -> None:
        if mode is TransferMode.NETASCII:
            file_mode = "t"
            encode = encode_netascii
        elif mode is TransferMode.OCTET:
            file_mode = "b"
            encode = identity
        else:
            raise NotImplementedError

        fh = None
        try:
            fh = open(local_filepath, mode="r" + file_mode)
            self._write(
                str(remote_filename),
                map(encode, iter(partial(fh.read, 512), b"")),
                mode,
            )
        finally:
            if fh is not None:
                fh.close()

    def write_file(
        self,
        remote_filename: str,
        data: Union[str, bytes, io.IOBase],
        mode: TransferMode = TransferMode.NETASCII,
    ) -> None:
        if mode is TransferMode.NETASCII:
            pass
        elif mode is TransferMode.OCTET:
            pass
        else:
            raise NotImplementedError

        if isinstance(data, str):
            data = io.StringIO(data)
        elif isinstance(data, bytes):
            data = io.BytesIO(data)

        if isinstance(data, io.StringIO):
            encode = encode_netascii
        else:
            encode = identity

        self._write(
            str(remote_filename), map(encode, iter(partial(data.read, 512), b"")), mode
        )

    def _read(
        self, remote_filename: str, mode: TransferMode = TransferMode.NETASCII
    ) -> Iterator[DataPacket]:
        self.packet_client.connect()
        rrq = ReadRequestPacket(filename=remote_filename, mode=mode)
        self.packet_client.send(rrq)

        block_number = 1

        while True:
            packet = self.packet_client.receive()
            packet = self._check_data_packet(packet, block_number)
            if packet is None:
                continue

            yield packet
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

    def _write(
        self,
        remote_filename: str,
        input_data: Iterator[bytes],
        mode: TransferMode = TransferMode.NETASCII,
    ) -> None:
        self.packet_client.connect()
        wrq = WriteRequestPacket(filename=remote_filename, mode=mode)
        logger.debug("Sending %s packet", wrq.packet_type.name)
        self.packet_client.send(wrq)

        # first response should be Ack with block number 0
        block_number = 0
        data_packet = None
        while True:
            packet = self.packet_client.receive()
            if isinstance(packet, AckPacket):
                if packet.block_number != block_number:
                    raise ValueError(
                        f"Ack received with block_number {packet.block_number}, "
                        f"expected {block_number}"
                    )
            elif isinstance(packet, ErrorPacket):
                raise ProtocolException(f"[{packet.error_code}] {packet.error_message}")
            else:
                raise ProtocolException(
                    f"Expected Ack or Err, received {packet.packet_type.name}"
                )

            if data_packet is not None and data_packet.end_of_data:
                # we already sent a data packet < 512, and have received ACK
                break

            chunk = next(input_data)
            block_number += 1
            if not chunk:
                # last data packet was 512 exactly, and also EOF, so send a 0 sized
                # data packet so server knows it is end of data
                data_packet = DataPacket(block_number, b"")
            else:
                data_packet = DataPacket(block_number, chunk)

            self.packet_client.send(data_packet)

    @staticmethod
    def _check_data_packet(packet: IPacket, block_number: int) -> DataPacket:
        if not isinstance(packet, DataPacket):
            raise ProtocolException(
                f"Expected {DataPacket.packet_type.name}, "
                f"got {packet.packet_type.name}"
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


class ServerFileResourceManager:
    # TODO handle file permissions at this level
    # TODO handle separate sessions reading/writing to same files

    __slots__ = (
        "_root_dir",
        "_session_managers",
    )

    def __init__(self, root_dir: Path) -> None:
        self._root_dir = root_dir.resolve()
        self._root_dir.mkdir(parents=True, exist_ok=True)
        self._session_managers = {}

    def get(self, client_addr) -> SessionFileResourceManager:
        if client_addr not in self._session_managers:
            instance = SessionFileResourceManager(self._root_dir)
            self._session_managers[client_addr] = instance
        else:
            instance = self._session_managers[client_addr]

        return instance

    def close(self, client_addr=None) -> None:
        if client_addr is not None:
            logger.debug("Closing Resource Manager for %s:%d", *client_addr)
            self._session_managers[client_addr].close()
            del self._session_managers[client_addr]
        else:
            for client_addr in self._session_managers.keys():
                logger.debug("Closing Resource Manager for %s:%d", *client_addr)
                self._session_managers[client_addr].close()
                del self._session_managers[client_addr]


class SessionFileResourceManager:

    __slots__ = ("_root_dir", "file_handle")

    def __init__(self, root_dir: Path) -> None:
        self._root_dir = root_dir
        self.file_handle: Optional[io.TextIOWrapper] = None

    def open(self, filepath: PathLike, mode: str) -> None:
        full_filepath = self._root_dir / to_path(filepath)
        if self._root_dir not in full_filepath.parents:
            raise IOError(f"Filepath '{filepath}' transcends root")

        self.file_handle = full_filepath.open(mode)

    def close(self) -> None:
        if self.file_handle is not None:
            self.file_handle.close()


class TftpServerState(ABC):
    def __init__(
        self, resource_manager: SessionFileResourceManager, packet: IPacket
    ) -> None:
        self.resource_manager = resource_manager
        self.packet = packet

    def __str__(self) -> str:
        return f"<{self.__class__.__name__}>"

    @abstractmethod
    def run(self, sock: socket.socket, client_addr: Tuple[str, int]) -> None:
        """Run the state, i.e. return some response to the client."""

    @abstractmethod
    def next(self, packet: IPacket) -> TftpServerState:
        """Transition to next server state."""


class ErrorServerState(TftpServerState):
    def __init__(
        self,
        resource_manager: SessionFileResourceManager,
        packet: IPacket,
        error_code: ErrorCodes,
        message: str = None,
    ) -> None:
        super().__init__(resource_manager, packet)
        self.packet = ErrorPacket(
            error_code=error_code.value,
            error_message=message if message is not None else error_code.name,
        )

    def run(self, sock: socket.socket, client_addr: Tuple[str, int]) -> None:
        sock.sendto(self.packet.data(), client_addr)
        self.resource_manager.close()

    def next(self, packet: IPacket) -> TftpServerState:
        pass


class ReadRequestServerState(TftpServerState):
    def __init__(
        self,
        resource_manager: SessionFileResourceManager,
        packet: ReadRequestPacket,
    ) -> None:
        super().__init__(resource_manager, packet)
        self.block_number = 1
        self.mode = packet.mode
        if self.mode is TransferMode.NETASCII:
            self.resource_manager.open(packet.filename, mode="rt")
        else:
            self.resource_manager.open(packet.filename, mode="rb")
        self.end_of_data = False

    def __str__(self) -> str:
        return f"<{self.__class__.__name__} (block {self.block_number:d})>"

    def run(self, sock: socket.socket, client_addr: Tuple[str, int]) -> None:
        raw_data = self.resource_manager.file_handle.read(512)

        if len(raw_data) < 512:
            self.end_of_data = True

        if self.mode is TransferMode.NETASCII:
            data = encode_netascii(raw_data)
        else:
            data = raw_data

        response = DataPacket(self.block_number, data)
        sock.sendto(response.data(), client_addr)

    def next(self, packet: IPacket) -> TftpServerState:
        if isinstance(packet, AckPacket):
            if packet.block_number == self.block_number:
                if not self.end_of_data:
                    self.block_number += 1
                    return self
                else:
                    # we have sent the last packet
                    return FinalServerState(self.resource_manager, self.packet)
            elif packet.block_number == self.block_number - 1:
                # we need to resend the packet
                self.resource_manager.file_handle.seek(self.block_number * 512, 0)
                return self
            else:
                return ErrorServerState(
                    self.resource_manager,
                    packet,
                    ErrorCodes.ILLEGAL_TFTP_OPERATION,
                )
        else:
            return ErrorServerState(
                self.resource_manager,
                packet,
                ErrorCodes.ILLEGAL_TFTP_OPERATION,
                f"Expected ACK, recevied {packet.packet_type.name}.",
            )


class WriteRequestServerState(TftpServerState):
    """Session state for a Write request. Client has sent a filepath in the initial
    request, we need to check the filepath and either return an Error or an Ack. We then
    expect N Data packets until a packet smaller than 512 bytes, at which point we send
    the last Ack and the session is over.
    """

    def __init__(
        self,
        resource_manager: SessionFileResourceManager,
        packet: WriteRequestPacket,
    ) -> None:
        super().__init__(resource_manager, packet)
        self.block_number = 0
        self.mode = packet.mode
        if self.mode is TransferMode.NETASCII:
            self.resource_manager.open(packet.filename, mode="wt")
        else:
            self.resource_manager.open(packet.filename, mode="wb")
        self.end_of_data = False

    def __str__(self) -> str:
        return f"<{self.__class__.__name__} (block {self.block_number:d})>"

    def run(self, sock: socket.socket, client_addr: Tuple[str, int]) -> None:
        response = AckPacket(self.block_number)
        logger.debug(
            "Sending %s (block %d)", response.packet_type.name, self.block_number
        )
        sock.sendto(response.data(), client_addr)

    def next(self, packet: IPacket) -> TftpServerState:
        if isinstance(packet, DataPacket):
            if packet.block_number == self.block_number + 1:
                # client has sent next block
                if self.mode is TransferMode.NETASCII:
                    data = decode_netascii(packet.raw_data)
                else:
                    data = packet.raw_data

                self.resource_manager.file_handle.write(data)
                self.block_number += 1

                if len(data) < 256:
                    # end of data, but we still need to send an ACK
                    return FinalServerState(
                        self.resource_manager,
                        self.packet,
                        final_word=AckPacket(self.block_number),
                    )
                else:
                    return self
            elif packet.block_number == self.block_number:
                # client has resent data packet, probably they did not receive ack,
                # resend ack with block number
                return self
            elif packet.block_number > self.block_number + 1:
                # we have missed a datapacket, resent ack with block number
                return self
            else:
                # client has resent packet less than previous, bad behavior
                return ErrorServerState(
                    self.resource_manager,
                    packet,
                    ErrorCodes.ILLEGAL_TFTP_OPERATION,
                )
        else:
            return ErrorServerState(
                self.resource_manager,
                packet,
                ErrorCodes.ILLEGAL_TFTP_OPERATION,
                f"Expected DATA, recevied {packet.packet_type.name}.",
            )


class FinalServerState(TftpServerState):
    def __init__(
        self,
        resource_manager: SessionFileResourceManager,
        packet: IPacket,
        final_word: IPacket = None,
    ) -> None:
        super().__init__(resource_manager, packet)
        self.final_word = final_word

    def run(self, sock: socket.socket, client_addr: Tuple[str, int]) -> None:
        if self.final_word is not None:
            logger.debug("Sending final word %s", self.final_word)
            sock.sendto(self.final_word.data(), client_addr)
        self.resource_manager.close()
        logger.info("Finalized connection with %s:%d", *client_addr)

    def next(self, packet: IPacket) -> TftpServerState:
        raise ProtocolException("Invalid state transition")


class InitialServerState(TftpServerState):
    def run(self, sock: socket.socket, client_addr: Tuple[str, int]) -> None:
        pass

    def next(self, packet: IPacket) -> TftpServerState:
        if isinstance(packet, WriteRequestPacket):
            return WriteRequestServerState(self.resource_manager, packet)
        elif isinstance(packet, ReadRequestPacket):
            return ReadRequestServerState(self.resource_manager, packet)
        else:
            return ErrorServerState(
                self.resource_manager,
                packet,
                ErrorCodes.ILLEGAL_TFTP_OPERATION,
                f"Expected Read or Write Request, received {packet.packet_type.name}",
            )


class TftpServerStateMachine:
    def __init__(
        self,
        sock: socket.socket,
        client_addr: Tuple[str, int],
        server_resource_manager: ServerFileResourceManager,
    ) -> None:
        self.sock = sock
        self.client_addr = client_addr
        self.resource_manager = server_resource_manager.get(client_addr)
        self.state = InitialServerState(self.resource_manager, None)
        self.state.run(self.sock, self.client_addr)

    def close(self) -> None:
        self.resource_manager.close()

    def run(self, packet) -> None:
        new_state = self.state.next(packet)
        logger.debug("State transition: %s -> %s", self.state, new_state)
        self.state = new_state
        self.state.run(self.sock, self.client_addr)


class TftpServerRequestHandler(socketserver.BaseRequestHandler):

    server: TftpServer

    def handle(self) -> None:
        data = self.request[0]
        sock = self.request[1]
        logger.debug("Data received from %s:%d", *self.client_address)
        packet = TftpPacketClient.read_packet(data)
        logger.debug(
            "%s:%d -> packet type %s", *self.client_address, packet.packet_type.name
        )

        client_state = self.server.clients.get(self.client_address)
        if self.server.clients.get(self.client_address) is None:
            client_state = TftpServerStateMachine(
                sock, self.client_address, self.server.resource_manager
            )
            self.server.clients[self.client_address] = client_state

        client_state.run(packet)
        if isinstance(client_state.state, FinalServerState):
            client_state.close()
            del self.server.clients[self.client_address]
            self.server.resource_manager.close(self.client_address)


class TftpServer(socketserver.ThreadingMixIn, socketserver.UDPServer):
    def __init__(
        self,
        listen_addr: str = "0.0.0.0",
        listen_port: int = 69,
        data_directory: Path = Path("."),
    ) -> None:
        self.clients: Dict[Tuple[str, int], TftpServerStateMachine] = {}
        self.resource_manager = ServerFileResourceManager(data_directory)
        super().__init__((listen_addr, listen_port), TftpServerRequestHandler)
        listen_addr_, listen_port_ = self.socket.getsockname()
        logger.info("Serving on %s:%d", listen_addr_, listen_port_)


def _parse_user_args():
    import argparse

    from . import VENDOR, APPLICATION_NAME
    from .util import cli
    from .util.io import parse_path

    argument_parser = argparse.ArgumentParser(
        prog="pyfiletransfer.tftp",
        description="Trivial File Transfer Protocol (TFTP) client and server.",
    )

    subcommands = argument_parser.add_subparsers(
        title="command", dest="command", required=True
    )
    client_parser = subcommands.add_parser("client", help="TFTP Client")
    server_parser = subcommands.add_parser("server", help="TFTP Server")
    cli.add_verbose(client_parser)
    cli.add_verbose(server_parser)

    client_parser.add_argument(
        "-s",
        "--server",
        type=str,
        help="IP or hostname of remote TFTP server.",
        required=True,
    )
    client_parser.add_argument(
        "-p",
        "--port",
        type=int,
        default=69,
        help="Port of remote TFTP server.",
    )
    client_parser.add_argument(
        "-m",
        "--mode",
        default=TransferMode.NETASCII,
        help="Transfer mode.",
        type=TransferMode,
        action=cli.EnumAction,
    )
    client_actions = client_parser.add_mutually_exclusive_group(required=True)
    client_actions.add_argument(
        "-d",
        "--download",
        help="Download file from remote server. First argument is the remote filepath, "
        "second argument is the local filepath.",
        nargs=2,
        metavar=("REMOTE", "LOCAL"),
        type=parse_path,
    )
    client_actions.add_argument(
        "-u",
        "--upload",
        help="Upload file to remote server. First argument is the local filepath, "
        "second argument is the remote filepath.",
        nargs=2,
        metavar=("LOCAL", "REMOTE"),
        type=parse_path,
    )

    server_parser.add_argument(
        "-l",
        "--listen",
        help="IP address or hostname to listen on. By default binds to all.",
        default="0.0.0.0",
        type=str,
    )
    server_parser.add_argument(
        "-p", "--port", help="Port to listen on.", type=int, default=69
    )
    server_parser.add_argument(
        "-d",
        "--data_dir",
        help="Directory to use a ROOT TFTP directory",
        type=parse_path,
        default=user_data_directory(VENDOR, APPLICATION_NAME) / "data",
    )

    parsed_args = argument_parser.parse_args()

    UserLogger().add_stderr(logging.DEBUG if parsed_args.verbose else logging.INFO)

    if parsed_args.command == "client":
        client = TftpClient(parsed_args.server)

        if parsed_args.download is not None:
            remote, local = parsed_args.download
            logger.debug("Downloading %s -> %s", remote, local)
            client.download_file(remote, local, mode=parsed_args.mode)
        else:
            local, remote = parsed_args.upload
            logger.debug("Uploading %s -> %s", local, remote)
            client.upload_file(remote, local, mode=parsed_args.mode)
    elif parsed_args.command == "server":
        with TftpServer(
            parsed_args.listen, parsed_args.port, data_directory=parsed_args.data_dir
        ) as server:
            try:
                server.serve_forever()
            except KeyboardInterrupt:
                logger.error("KeyboardInterrupt detected, exiting")
                sys.exit(1)
    else:
        raise argparse.ArgumentError(
            parsed_args.command, f"Unrecognized command {parsed_args.command}"
        )


if __name__ == "__main__":
    _parse_user_args()
