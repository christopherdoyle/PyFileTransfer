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
