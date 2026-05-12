from frozendict import frozendict

from binary_function import BinaryFunction
from engine_types import (
    Arg,
    BinaryOp,
    CallSite,
    ConditionalExpression,
    ConditionalSite,
    MemoryAccess,
    MemoryAccessType,
    UnaryOp,
)
from pcode_engine import Engine
from project import Project


class TestARM:

    def test_read_double_calls_value_extract_buf(self):
        # ltrace binary `read_double`: calls value_extract_buf(a1, &var14, a3)
        CODE = b"\x10\x48\x2d\xe9\x08\xb0\x8d\xe2\x1c\xd0\x4d\xe2\x18\x00\x0b\xe5\x1c\x10\x0b\xe5\x20\x20\x0b\xe5\x14\x30\x4b\xe2\x18\x00\x1b\xe5\x03\x10\xa0\xe1\x20\x20\x1b\xe5\xa4\xf5\xff\xeb\x00\x30\xa0\xe1\x00\x00\x53\xe3\x01\x00\x00\xaa\x00\x30\xe0\xe3\x04\x00\x00\xea\x14\x40\x4b\xe2\x18\x00\x94\xe8\x1c\x20\x1b\xe5\x18\x00\x82\xe8\x00\x30\xa0\xe3\x03\x00\xa0\xe1\x08\xd0\x4b\xe2\x10\x48\xbd\xe8\x1e\xff\x2f\xe1"
        ADDR = 0x000300F8
        VALUE_EXTRACT_BUF = 0x0002D7B8

        project = Project("ARM:LE:32:v7")
        engine = Engine(BinaryFunction(ADDR, CODE, project))
        engine.analyze()

        assert len(engine.callsites) == 1
        cs = engine.callsites[0]
        assert cs.target == VALUE_EXTRACT_BUF
        assert cs.args[0] == Arg(0)
        assert cs.args[2] == Arg(2)
        # arg1 is a pointer to the local var14 buffer on the stack frame
        assert isinstance(cs.args[1], BinaryOp)


class TestARMConditionalTailCall:
    # ltrace binary `__libelf_set_rawdata`:
    #   if (a0 == 0) return 1;
    #   else return __libelf_set_rawdata_wrlock();
    CODE = b"\x00\x00\x50\xe3\x00\x00\x00\x0a\x2c\xff\xff\xea\x01\x00\xa0\xe3\x1e\xff\x2f\xe1"
    ADDR = 0x35794
    TAIL_CALL_TARGET = 0x35454

    def test_callsites(self):
        project = Project("ARM:LE:32:v7")
        engine = Engine(BinaryFunction(self.ADDR, self.CODE, project))
        engine.analyze()

        assert len(engine.callsites) == 1
        assert engine.callsites[0] == CallSite(0x3579C, self.TAIL_CALL_TARGET, frozendict({0: Arg(0)}))

    def test_conditional_site(self):
        # BEQ at 0x35798 branches to the constant-return path; fall-through tail-calls
        project = Project("ARM:LE:32:v7")
        engine = Engine(BinaryFunction(self.ADDR, self.CODE, project))
        engine.analyze()

        assert len(engine.conditional_sites) == 1
        assert engine.conditional_sites[0] == ConditionalSite(
            addr=0x35798,  # BEQ instruction
            condition=BinaryOp(Arg(0), 0, "=="),
            iftrue=0x357A0,
            iffalse=0x3579C,
        )

    def test_return_values(self):
        project = Project("ARM:LE:32:v7")
        engine = Engine(BinaryFunction(self.ADDR, self.CODE, project))
        engine.analyze()

        tail_call = CallSite(0x3579C, self.TAIL_CALL_TARGET, frozendict({0: Arg(0)}))
        assert engine.return_values == {1, tail_call}


class TestARMMemoryAccess:
    # ltrace binary `arch_fetch_param_pack_end`: clears bit 1 of *(a0 + 0x170) and returns a0
    # Stack-saving PUSH {R11}; SUB SP, SP, #0xC; STR R0, [R11,#var_8]; (frame-pointer prologue)
    # LDR R2, [R11,#var_8]; LDRB R3, [R2,#0x170]; BIC R3, R3, #2; STRB R3, [R2,#0x170]; (body)
    # MOV SP, R11; POP {R11}; BX LR; (epilogue)
    CODE = b"\x04\xb0\x2d\xe5\x00\xb0\x8d\xe2\x0c\xd0\x4d\xe2\x08\x00\x0b\xe5\x08\x20\x1b\xe5\x70\x31\xd2\xe5\x02\x30\xc3\xe3\x70\x31\xc2\xe5\x00\xd0\x8b\xe2\x00\x08\xbd\xe8\x1e\xff\x2f\xe1"
    ADDR = 0x14890

    def test_load_and_store(self):
        project = Project("ARM:LE:32:v7")
        engine = Engine(BinaryFunction(self.ADDR, self.CODE, project))
        engine.analyze()

        load = MemoryAccess(0x148A4, Arg(0), 0x170, MemoryAccessType.LOAD)
        stored_val = BinaryOp(load, UnaryOp(2, "~"), "&")
        store = MemoryAccess(0x148AC, Arg(0), 0x170, MemoryAccessType.STORE, stored_val)

        assert load in engine.memory_accesses
        assert store in engine.memory_accesses

    def test_returns_arg0(self):
        # The function returns its first argument unchanged
        project = Project("ARM:LE:32:v7")
        engine = Engine(BinaryFunction(self.ADDR, self.CODE, project))
        engine.analyze()

        assert engine.return_values == {Arg(0)}


class TestARMConditionalExecution:
    # ltrace binary `mbrlen`:
    #   v3 = &internal;
    #   if (a2 != 0) v3 = a2;          // MOVNE R3, R2 — ARM conditional execution
    #   return mbrtowc(0, a0, a1, v3);
    CODE = b"\x00\x00\x52\xe3\x1c\x30\x9f\xe5\x10\x40\x2d\xe9\x02\x30\xa0\x11\x01\x20\xa0\xe1\x00\x10\xa0\xe1\x00\x00\xa0\xe3\xe4\xa6\xff\xeb\x10\x40\xbd\xe8\x1e\xff\x2f\xe1"
    ADDR = 0xAE1D4
    MBRTOWC = 0x97D88

    def test_movne_creates_conditional_site(self):
        project = Project("ARM:LE:32:v7")
        engine = Engine(BinaryFunction(self.ADDR, self.CODE, project))
        engine.analyze()

        # MOVNE R3, R2: the cbranch lifts to a "skip" with iftrue == iffalse == next addr
        assert len(engine.conditional_sites) == 1
        cs = engine.conditional_sites[0]
        assert cs.addr == 0xAE1E0
        assert cs.condition == BinaryOp(Arg(2), 0, "==")
        assert cs.iftrue == cs.iffalse == 0xAE1E4

    def test_callsite_conditional_argument(self):
        project = Project("ARM:LE:32:v7")
        engine = Engine(BinaryFunction(self.ADDR, self.CODE, project))
        engine.analyze()

        assert len(engine.callsites) == 1
        cs = engine.callsites[0]
        assert cs.target == self.MBRTOWC

        # arg[3] picks &internal or a2 depending on (a2 == 0)
        condsite = engine.conditional_sites[0]
        # When (a2 == 0) is true, v3 stays as the loaded literal *0xae1fc (&internal).
        # When false, the MOVNE executes and v3 becomes a2.
        assert cs.args[3] == ConditionalExpression(condsite, UnaryOp(0xAE1FC, "*"), Arg(2))

    def test_function_has_single_block(self):
        # ARM MOVNE produces a CBRANCH-to-next-instruction; this should NOT split the
        # block or create a phantom self-loop in the CFG.
        project = Project("ARM:LE:32:v7")
        bf = BinaryFunction(self.ADDR, self.CODE, project)
        assert len(bf.blocks_dict_start_address) == 1
        assert self.ADDR in bf.blocks_dict_start_address


class TestARMConditionalReturn:
    # ltrace binary `do_encoding`:
    #   v1 = *(a0 + 0x24);
    #   if (*(v1 + 0x34)) return -1;                  // BXNE LR pattern
    #   tmp = *(v1 + 0x24); other = *(v1 + 0x28);
    #   return tmp == other ? other : 0;
    CODE = b"\x24\x30\x90\xe5\x34\x20\x93\xe5\x00\x00\x52\xe3\x00\x00\xe0\x13\x1e\xff\x2f\x11\x24\x00\x83\xe2\x05\x00\x90\xe8\x02\x00\x50\xe1\x02\x00\xa0\x01\x00\x00\xa0\x13\x1e\xff\x2f\xe1"
    ADDR = 0x968D0

    def test_bxne_lr_does_not_truncate_function(self):
        # The BXNE LR is a conditional return; iteration must continue past it.
        project = Project("ARM:LE:32:v7")
        bf = BinaryFunction(self.ADDR, self.CODE, project)
        blk = bf.blocks_dict_start_address[self.ADDR]
        # Without conditional-return handling the block would terminate at the BXNE (0x968e3).
        assert blk.end >= 0x968F8

    def test_loads_after_conditional_return_are_visible(self):
        # The LDM after the conditional return loads from *(v1 + 0x24) and *(v1 + 0x28).
        project = Project("ARM:LE:32:v7")
        engine = Engine(BinaryFunction(self.ADDR, self.CODE, project))
        engine.analyze()

        v1 = MemoryAccess(0x968D0, Arg(0), 0x24, MemoryAccessType.LOAD)
        assert MemoryAccess(0x968D4, v1, 0x34, MemoryAccessType.LOAD) in engine.memory_accesses
        # LDM expands the base into separate loads at offsets 0 and 4 of (v1 + 0x24)
        lhs = MemoryAccess(0x968E8, v1, 0x24, MemoryAccessType.LOAD)
        rhs = MemoryAccess(0x968E8, v1, 0x28, MemoryAccessType.LOAD)
        assert lhs in engine.memory_accesses
        assert rhs in engine.memory_accesses

    def test_conditional_sites_count(self):
        # 4 conditional ARM instructions: MOVNE, BXNE, MOVEQ, MOVNE
        project = Project("ARM:LE:32:v7")
        engine = Engine(BinaryFunction(self.ADDR, self.CODE, project))
        engine.analyze()
        assert len(engine.conditional_sites) == 4

    def test_post_conditional_return_path_return_values(self):
        # When the conditional return is not taken, the function returns either
        # *(v1 + 0x28) (MOVEQ path) or 0 (MOVNE path) depending on the second compare.
        project = Project("ARM:LE:32:v7")
        engine = Engine(BinaryFunction(self.ADDR, self.CODE, project))
        engine.analyze()

        v1 = MemoryAccess(0x968D0, Arg(0), 0x24, MemoryAccessType.LOAD)
        rhs = MemoryAccess(0x968E8, v1, 0x28, MemoryAccessType.LOAD)
        # The conditional-return value (-1) is not captured here because the engine
        # uses the block's final-instruction state for return values, not intermediate
        # conditional-return points. The two captured values come from the MOVEQ/MOVNE
        # at the end of the block.
        assert 0 in engine.return_values
        assert rhs in engine.return_values
