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

    def test_store_memory_access_with_callsite_base(self):
        # sshd binary `BN_new` function
        CODE = b"<\x1c\x00_'\xbd\xff\xd8'\x9c'\xe0\xaf\xb0\x00 <\x10\x00Z$\x04\x00\x14\xaf\xbf\x00$\xaf\xbc\x00\x18&\x057\x08\x8f\x99\x82\xd4\x03 \xf8\t$\x06\x01\x10\x14@\x00\x0b\x8f\xbc\x00\x18$\x02\x01\x11\x8f\x99\x81\xec$\x04\x00\x03$\x05\x00q$\x06\x00A\xaf\xa2\x00\x10\x03 \xf8\t&\x077\x08\x08\x11\xe6~\x00\x00\x10!$\x03\x00\x01\xac@\x00\x04\xac@\x00\x0c\xac@\x00\x08\xacC\x00\x10\xac@\x00\x00\x8f\xbf\x00$\x8f\xb0\x00 \x03\xe0\x00\x08'\xbd\x00("
        ADDR = 0x00479980

        project = Project("MIPS:BE:32:default")
        bin_func = BinaryFunction(ADDR, CODE, project)
        engine = Engine(bin_func)

        assert len(engine.memory_accesses) == 5

        base = engine.callsites[0]
        assert MemoryAccess(0x004799F4, base, 0, MemoryAccessType.STORE, 0) in engine.memory_accesses  # The main test

        assert MemoryAccess(0x004799E4, base, 4, MemoryAccessType.STORE, 0) in engine.memory_accesses
        assert MemoryAccess(0x004799EC, base, 8, MemoryAccessType.STORE, 0) in engine.memory_accesses
        assert MemoryAccess(0x004799E8, base, 0xC, MemoryAccessType.STORE, 0) in engine.memory_accesses
        assert MemoryAccess(0x004799F0, base, 0x10, MemoryAccessType.STORE, 1) in engine.memory_accesses
