from frozendict import frozendict
from binary_function import BinaryFunction
from project import Project
from pcode_engine import Engine
from engine_types import (
    Arg,
    BinaryOp,
    CallSite,
    ConditionalExpression,
    ConditionalSite,
    MemoryAccess,
    MemoryAccessType,
    Register,
    UnaryOp,
)


class TestEngineMIPSEL:
    def test_engine_mipsel_1(self):
        CODE = b"\xe0\xff\xbd'\x00\x00\x02<\x14\x00\xb0\xaf(\x0fB$\x1c\x00\xbf\xaf\x18\x00\xb1\xaf\t\xf8@\x00\x00\x00\x10<\xe0\x0e\x02\x92$\x00@\x14\x00\x00\x11<\xe1\x0e\"\x92\x01\x00B$\xff\x00B0\x02\x00C,\n\x00`\x14\xe1\x0e\"\xa2\x00\x00\x02<\x08\x0fB$\t\xf8@\x00\x00\x00\x00\x00\x03\x00@\x10\x01\x00\x03$\x00\x00\x02<0\x0fC\xa0\xe1\x0e \xa2\x00\x00\x02<\x18\x0fB$\t\xf8@\x00\xe0\x0e\x00\xa2\x00\x00\x02<<\x0fB$\t\xf8@\x00\x00\x00\x84\x8f\x00\x00\x02<8\x0fE\x8c\x1c\x00\xbf\x8f\x18\x00\xb1\x8f\x14\x00\xb0\x8f\x00\x00\x04<\x00\x00\x19<\xe4\x0e\x84$\xe2\x04\xa5$,\x0f9'\x08\x00 \x03 \x00\xbd'\x00\x00\x02<\x10\x0fB$\t\xf8@\x00\x00\x00\x00\x00\x04\x00@\x14\x00\x00\x02<\x00\x00\x02<0\x0f@\xa0\x00\x00\x02<\x87\x02\x00\x08\xe1\x0e@\xa0"
        ADDR = 0x000009B4

        project = Project("MIPS:LE:32:default")
        bin_func = BinaryFunction(ADDR, CODE, project)
        engine = Engine(bin_func)

        expected_conditional_sites = {
            ConditionalSite(0x9D8, BinaryOp(UnaryOp(0xEE0, "*"), 0, "!="), 0xA6C, 0x9E0),
            ConditionalSite(
                0x9F0, BinaryOp(BinaryOp(BinaryOp(UnaryOp(0xEE1, "*"), 1, "+"), 0xFF, "&"), 2, "<"), 0xA1C, 0x9F8
            ),
            ConditionalSite(0xA7C, BinaryOp(CallSite(0xA74, 0xF10, frozendict()), 0, "!="), 0xA90, 0xA84),
            ConditionalSite(0xA08, BinaryOp(CallSite(0xA00, 0xF08, frozendict()), 0, "=="), 0xA18, 0xA10),
        }
        assert expected_conditional_sites == set(engine.conditional_sites)

        expected_callsites = {
            CallSite(0x9CC, 0xF28, frozendict()),
            CallSite(0xA74, 0xF10, frozendict()),
            CallSite(0xA00, 0xF08, frozendict()),
            CallSite(0xA24, 0xF18, frozendict()),
            CallSite(
                0xA34,
                0xF3C,
                frozendict({0: MemoryAccess(0xA34, Register(112, 0xA34, bin_func), 0, MemoryAccessType.LOAD)}),
            ),
            CallSite(0xA64, 0xF2C, frozendict({0: 0xEE4, 1: BinaryOp(UnaryOp(0xF38, "*"), 1250, "+")})),
        }

        assert expected_callsites == set(engine.callsites)


class TestEngineMIPSBE:
    # sshd binary `sshd_hostkey_sign` function
    def test_different_states_merged_into_conditional_expression(self):
        CODE = b"<\x1c\x00_'\xbd\xff\xc8'\x9c'\xe0\xaf\xb0\x000\x00\xc0@!\xaf\xbf\x004\x00\xe0\x80!\xaf\xbc\x00 <\t\x00_\x8f\xa3\x00H\x10\x80\x00\x14\x8f\xa2\x00L\x8d%\x90<'\xa6\x00(\x10\xa0\x00\x05\xaf\xa2\x00\x10\x01\x00(!\x8f\x99\x83P\x08\x10\x0f\xb6\x00`8!\x8f\x99\x83T\x01\x00(!\x00`8!\x03 \xf8\t\x00\x00\x00\x00\x00\x02\x17\xc2\x10@\x00\x16\x8f\xbc\x00 <\x04\x00W\x08\x10\x0f\xcc$\x84;@\x8d$\x90<P\x80\x00\x14\xaf\xa2\x00\x14\x8f\x99\x83P\x00\xa0 !\x00\xc0(!\xaf\xa2\x00\x10'\xa6\x00(\x03 \xf8\t\x00`8!\x04A\x00\x07\x8f\xbc\x00 <\x04\x00W$\x84;T<\x05\x00W\x8f\x99\x80\xe4\x03 \xf8\t$\xa5P\xdc\x12\x00\x00\x18\x8f\xa2\x00(\x08\x10\x0f\xe9\xae\x02\x00\x00<\x04\x00_\xaf\xa3\x00\x10\x8f\x82\x83X\x8f\x99\x83\\\x8c\x84\x90D\x8cB\x00\x00\x03 \xf8\t\xaf\xa2\x00\x18\x10@\x00\x0c\x8f\xbc\x00 \x8f\x99\x80\xb4\x03 \xf8\t\x00@ !<\x04\x00W\x8f\xbc\x00 <\x05\x00W$\x84;l$\xa5P\xdc\x8f\x99\x80\xe4\x03 \xf8\t\x00@0!\x8f\xbf\x004\x00\x00\x10!\x8f\xb0\x000\x03\xe0\x00\x08'\xbd\x008"
        ADDR = 0x00403E7C

        project = Project("MIPS:BE:32:default")
        bin_func = BinaryFunction(ADDR, CODE, project)
        engine = Engine(bin_func)

        expected_result = ConditionalExpression(
            engine.addr_to_conditional_site[0x00403EAC],
            UnaryOp(0x5EAB30, "*"),
            UnaryOp(0x5EAB34, "*"),
        )

        assert engine.instructions_state[0x00403ED8].regs[project.context.registers["t9"].offset] == expected_result

    def test_callsite_argument_is_arg(self):
        # sshd binary `RAND_add` function
        CODE = b"'\xbd\xff\xd0\xaf\xa4\x00\x18\xaf\xa5\x00\x1c\xaf\xa6\x00 \xaf\xa7\x00$\xaf\xbf\x00,\x0c\x121\x1b\x00\x00\x00\x00\x8f\xa4\x00\x18\x8f\xa5\x00\x1c\x8f\xa6\x00 \x10@\x00\x06\x8f\xa7\x00$\x8cY\x00\x0c\x13 \x00\x03\x8f\xbf\x00,\x03 \x00\x08'\xbd\x000\x8f\xbf\x00,\x03\xe0\x00\x08'\xbd\x000"
        ADDR = 0x0048C610

        project = Project("MIPS:BE:32:default")
        bin_func = BinaryFunction(ADDR, CODE, project)
        engine = Engine(bin_func)

        assert engine.callsites[1].args == frozendict({0: Arg(0), 1: Arg(1), 2: Arg(2), 3: Arg(3)})

    def test_load_memory_access_sanity(self):
        # sshd binary `fileno` function
        CODE = b"<\x1c\x00\t'\x9c&@\x03\x99\xe0!'\xbd\xff\xd8\xaf\xb1\x00\x1c\xaf\xbc\x00\x10\xaf\xb0\x00\x18\xaf\xbf\x00$\xaf\xb2\x00 \x8c\x91\x008\x16 \x00\x19\x00\x80\x80!|\x03\xe8;\x8c\x82\x00D$r\x8b\xa0\x10R\x00\x11$\x84\x00<$\x02\x00\x01\xc2\x05\x00<\x14\xb1\x00\x06\x00\x00\x18!\x00@\x18!\xe2\x03\x00<\x10`\xff\xfa\x00\x00\x00\x00\x00\x00\x00\x0fT`\x00\x06\xae\x12\x00D\x8f\x99\xa8\x08\x03 \xf8\t\x00\x00\x00\x00\x8f\xbc\x00\x10\xae\x12\x00D\x8e\x02\x00@$B\x00\x01\xae\x02\x00@\x8f\x99\xa8\xa8\x03 \xf8\t\x02\x00 !\x16 \x00\x15\x00@\x90!\x8e\x03\x00@$c\xff\xff\x14`\x00\x11\xae\x03\x00@\xae\x00\x00D&\x04\x00<\x00\x00\x00\x0f\xc2\x03\x00<\x02 \x10!\xe2\x02\x00<\x10@\xff\xfc\x00\x00\x00\x00(c\x00\x02\x14`\x00\x07\x8f\xbf\x00$$\x05\x00\x81$\x06\x00\x01\x00\x008!$\x02\x10\x8e\x00\x00\x00\x0c\x8f\xbf\x00$\x02@\x10!\x8f\xb2\x00 \x8f\xb1\x00\x1c\x8f\xb0\x00\x18\x03\xe0\x00\x08'\xbd\x00("
        ADDR = 0x005601A0

        project = Project("MIPS:BE:32:default")
        bin_func = BinaryFunction(ADDR, CODE, project)
        engine = Engine(bin_func)

        assert MemoryAccess(0x005601C4, Arg(0), 0x38, MemoryAccessType.LOAD) in engine.memory_accesses
        assert MemoryAccess(0x005601D4, Arg(0), 0x44, MemoryAccessType.LOAD) in engine.memory_accesses
        assert MemoryAccess(0x005601E8, Arg(0), 0x3C, MemoryAccessType.LOAD) in engine.memory_accesses
        assert MemoryAccess(0x00560224, Arg(0), 0x40, MemoryAccessType.LOAD) in engine.memory_accesses
        assert MemoryAccess(0x00560244, Arg(0), 0x40, MemoryAccessType.LOAD) in engine.memory_accesses
        assert MemoryAccess(0x00560260, Arg(0), 0x3C, MemoryAccessType.LOAD) in engine.memory_accesses
