from frozendict import frozendict
from binary_function import BinaryFunction
from engine_types import Arg, CallSite, MemoryAccess, MemoryAccessType, UnaryOp
from pcode_engine import Engine
from project import Project


class TestMemoryAccess:
    def test_store_memory_access_sanity(self):
        # sshd binary `BN_RECP_CTX_new` function
        CODE = b"<\x1c\x00_<\x05\x00\\'\x9c'\xe0'\xbd\xff\xd8$\x04\x004\x8f\x99\x82\xd4$\xa5\x8e`\xaf\xbf\x00$\xaf\xbc\x00\x10\x03 \xf8\t$\x06\x00K\x10@\x00\x06\x00@ !\x0c\x133\xb8\xaf\xa2\x00\x18$\x03\x00\x01\x8f\xa2\x00\x18\xacC\x000\x8f\xbf\x00$\x03\xe0\x00\x08'\xbd\x00("
        ADDR = 0x004CCF2C

        project = Project("MIPS:BE:32:default")
        bin_func = BinaryFunction(ADDR, CODE, project)
        engine = Engine(bin_func)

        assert len(engine.memory_accesses) == 1
        expected_access = MemoryAccess(
            addr=0x004CCF70,
            base=CallSite(
                addr=0x004CCF50,
                target=UnaryOp(0x005EAAB4, "*"),
                args=frozendict({0: 52, 1: 0x005B8E60, 2: 75}),
            ),
            offset=0x30,
            access_type=MemoryAccessType.STORE,
            stored_value=1,
        )
        assert expected_access in engine.memory_accesses

    def test_load_memory_access_sanity(self):
        # sshd binary `PKCS7_get_attribute` function
        CODE = b"\x08\x12\x8b\xeb\x8c\x84\x00\x18"
        ADDR = 0x004A4EB8

        project = Project("MIPS:BE:32:default")
        bin_func = BinaryFunction(ADDR, CODE, project)
        engine = Engine(bin_func)

        assert len(engine.memory_accesses) == 1
        expected_access = MemoryAccess(
            addr=0x004A4EB8,
            base=Arg(0),
            offset=0x18,
            access_type=MemoryAccessType.LOAD,
        )
        assert expected_access in engine.memory_accesses
