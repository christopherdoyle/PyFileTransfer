import pytest

from pyfiletransfer import tftp


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
        assert expected.data == actual.data

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
            b"\x00\x00"
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
            b"\x00\x00"
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
