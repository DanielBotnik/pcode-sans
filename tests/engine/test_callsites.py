from frozendict import frozendict
from binary_function import BinaryFunction
from engine_types import Arg, CallSite
from pcode_engine import Engine
from project import Project


class TestCallSites:
    def test_callsite_with_forwarded_stack_arguments(self):
        # sshd binary `EVP_EncryptInit_ex` function
        CODE = b"'\xbd\xff\xd8\xaf\xbf\x00$\x8f\xa2\x008\xaf\xa2\x00\x10$\x02\x00\x01\x0c\x12=_\xaf\xa2\x00\x14\x8f\xbf\x00$\x03\xe0\x00\x08'\xbd\x00("
        ADDR = 0x0048FA90

        project = Project("MIPS:BE:32:default")
        bin_func = BinaryFunction(ADDR, CODE, project)
        engine = Engine(bin_func)

        assert len(engine.callsites) == 1
        assert engine.callsites[0] == CallSite(
            0x0048FAA4,
            0x0048F57C,
            args=frozendict({0: Arg(0), 1: Arg(1), 2: Arg(2), 3: Arg(3), 4: Arg(4), 5: 1}),
        )
