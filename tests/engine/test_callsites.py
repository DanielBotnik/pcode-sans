from frozendict import frozendict
from binary_function import BinaryFunction
from engine_types import Arg, CallSite, UnaryOp
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

    def test_callsite_with_forwarded_arg_arguments(self):
        # sshd binary `DHparams_print` function
        CODE = b"$\x06\x00\x04\x08\x13\x88\xdc\x00\x008!"
        ADDR = 0x004E3C84

        project = Project("MIPS:BE:32:default")
        bin_func = BinaryFunction(ADDR, CODE, project)
        engine = Engine(bin_func)

        assert len(engine.callsites) == 1
        assert engine.callsites[0] == CallSite(
            addr=0x004E3C88,
            target=0x004E2370,
            args=frozendict({0: Arg(0), 1: Arg(1), 2: 4, 3: 0}),
        )

    def test_indirect_branch_is_callsite(self):
        # sshd binary `i2d_PKCS7_NDEF` function
        CODE = b"<\x1c\x00_<\x06\x00^'\x9c'\xe0\x8f\x99\x9a \x03 \x00\x08$\xc6\xd2\x84"
        ADDR = 0x004A1678
        PKCS7_it = 0x005DD284

        project = Project("MIPS:BE:32:default")
        bin_func = BinaryFunction(ADDR, CODE, project)
        engine = Engine(bin_func)

        assert len(engine.callsites) == 1
        expected_callsite = CallSite(
            addr=0x004A1688,
            target=UnaryOp(0x5EC200, "*"),
            args=frozendict({0: Arg(0), 1: Arg(1), 2: PKCS7_it}),
        )
        assert expected_callsite in engine.callsites

    def test_callsite_with_many_stack_arguments(self):
        CODE = b"<\x1c\x00_\x00\xa08!'\x9c'\xe0<\x05\x00['\xbd\xff\xc8\x00\x800!\x8f\x99\x99l\x8f\x84\x99\xb0$\xa5\x91\x18\xaf\xbf\x004\xaf\xbc\x00(\xaf\xa0\x00\x10\xaf\xa0\x00\x14\xaf\xa0\x00\x18\xaf\xa0\x00\x1c\x03 \xf8\t\xaf\xa0\x00 \x8f\xbf\x004\x03\xe0\x00\x08'\xbd\x008"
        ADDR = 0x004A0390

        project = Project("MIPS:BE:32:default")
        bin_func = BinaryFunction(ADDR, CODE, project)
        engine = Engine(bin_func)

        assert len(engine.callsites) == 1
        expected_callsite = CallSite(
            addr=0x004A03CC,
            target=UnaryOp(0x005EC14C, "*"),
            args=frozendict(
                {
                    0: UnaryOp(0x005EC190, "*"),
                    1: 0x005A9118,
                    2: Arg(0),
                    3: Arg(1),
                    4: 0,
                    5: 0,
                    6: 0,
                    7: 0,
                    8: 0,
                }
            ),
        )
        assert expected_callsite in engine.callsites
