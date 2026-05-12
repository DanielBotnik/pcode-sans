from frozendict import frozendict

from binary_function import BinaryFunction
from engine_types import (
    Arg,
    BinaryOp,
    CallSite,
    ConditionalExpression,
    ConditionalSite,
    Loop,
    MemoryAccess,
    MemoryAccessType,
    Register,
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


class TestARMMultipleLoads:
    # ltrace binary `dlvsym_doit`:
    #   _dl_vsym(a0[0], a0[1], a0[2], a0[3]);
    #   a0[4] = result;
    # Uses LDR + LDM to fetch 4 args, BL, then STR for the result.
    CODE = b"\x10\x40\x2d\xe9\x00\x40\xa0\xe1\x04\x10\x94\xe5\x00\x00\x90\xe5\x08\x20\x84\xe2\x0c\x00\x92\xe8\xe3\x14\x00\xeb\x10\x00\x84\xe5\x10\x40\xbd\xe8\x1e\xff\x2f\xe1"
    ADDR = 0xAE0C4
    DL_VSYM = 0xB3470

    def test_callsite_args_from_arg0_struct(self):
        project = Project("ARM:LE:32:v7")
        engine = Engine(BinaryFunction(self.ADDR, self.CODE, project))
        engine.analyze()

        assert len(engine.callsites) == 1
        cs = engine.callsites[0]
        assert cs.target == self.DL_VSYM
        assert cs.args[0] == MemoryAccess(0xAE0D0, Arg(0), 0, MemoryAccessType.LOAD)
        assert cs.args[1] == MemoryAccess(0xAE0CC, Arg(0), 0x4, MemoryAccessType.LOAD)
        assert cs.args[2] == MemoryAccess(0xAE0D8, Arg(0), 0x8, MemoryAccessType.LOAD)
        assert cs.args[3] == MemoryAccess(0xAE0D8, Arg(0), 0xC, MemoryAccessType.LOAD)

    def test_no_spurious_callee_save_args(self):
        # PUSH {R4, LR} stores callee-saves at sp+0 and sp+4. Those must NOT leak
        # into the callsite's args dict.
        project = Project("ARM:LE:32:v7")
        engine = Engine(BinaryFunction(self.ADDR, self.CODE, project))
        engine.analyze()
        cs = engine.callsites[0]
        assert set(cs.args.keys()) == {0, 1, 2, 3}

    def test_stores_return_value_to_struct(self):
        # STR R0, [R4, #0x10] stores the call's return value at a0[4]
        project = Project("ARM:LE:32:v7")
        engine = Engine(BinaryFunction(self.ADDR, self.CODE, project))
        engine.analyze()

        store = next(
            ma for ma in engine.memory_accesses
            if ma.access_type == MemoryAccessType.STORE
        )
        assert store.addr == 0xAE0E0
        assert store.base == Arg(0)
        assert store.offset == 0x10
        assert isinstance(store.stored_value, CallSite)
        assert store.stored_value.target == self.DL_VSYM


class TestARMConditionalCallChain:
    # ltrace binary `local_strdup`:
    #   v2 = strlen(a0) + 1;
    #   v3 = malloc(v2);
    #   if (v3) return memcpy(v3, a0, v2); else return 0;
    # Uses BLNE (conditional call) and MOVEQ/MOVNE.
    CODE = b"\x70\x40\x2d\xe9\x00\x50\xa0\xe1\x5d\x11\xff\xeb\x01\x40\x80\xe2\x04\x00\xa0\xe1\xeb\x09\xff\xeb\x00\x30\x50\xe2\x03\x00\xa0\x01\x05\x10\xa0\x11\x04\x20\xa0\x11\x5d\x17\xff\x1b\x70\x40\xbd\xe8\x1e\xff\x2f\xe1"
    ADDR = 0x9D39C
    STRLEN = 0x61920
    MALLOC = 0x5FB64
    MEMCPY = 0x63140

    def test_three_callsites_in_order(self):
        project = Project("ARM:LE:32:v7")
        engine = Engine(BinaryFunction(self.ADDR, self.CODE, project))
        engine.analyze()

        assert len(engine.callsites) == 3
        assert engine.callsites[0].target == self.STRLEN
        assert engine.callsites[1].target == self.MALLOC
        assert engine.callsites[2].target == self.MEMCPY

    def test_strlen_called_with_arg0(self):
        project = Project("ARM:LE:32:v7")
        engine = Engine(BinaryFunction(self.ADDR, self.CODE, project))
        engine.analyze()

        assert engine.callsites[0].args[0] == Arg(0)

    def test_malloc_argument_is_strlen_plus_one(self):
        project = Project("ARM:LE:32:v7")
        engine = Engine(BinaryFunction(self.ADDR, self.CODE, project))
        engine.analyze()

        strlen_call = engine.callsites[0]
        assert engine.callsites[1].args[0] == BinaryOp(strlen_call, 1, "+")

    def test_blne_creates_conditional_execution_chain(self):
        # 4 ARM conditional instructions: MOVEQ R0, R3; MOVNE R1, R5; MOVNE R2, R4; BLNE memcpy
        project = Project("ARM:LE:32:v7")
        engine = Engine(BinaryFunction(self.ADDR, self.CODE, project))
        engine.analyze()

        assert len(engine.conditional_sites) == 4


class TestARMStackSpill:
    # ltrace binary `memstream_destroy`:
    #   return free(a0[1]);
    # Prologue spills R0 to a stack local, body reloads it — exercises STR+LDR via R11.
    CODE = b"\x00\x48\x2d\xe9\x04\xb0\x8d\xe2\x08\xd0\x4d\xe2\x08\x00\x0b\xe5\x08\x30\x1b\xe5\x04\x30\x93\xe5\x03\x00\xa0\xe1\x2d\xb4\x00\xeb\x04\xd0\x4b\xe2\x00\x48\xbd\xe8\x1e\xff\x2f\xe1"
    ADDR = 0x32938
    FREE = 0x5FA10

    def test_only_one_memory_access(self):
        # Despite PUSH/STR/LDR/POP, the only "real" memory access is the *(a0+4) deref.
        # Everything else is on the stack and should be tracked there, not in memory_accesses.
        project = Project("ARM:LE:32:v7")
        engine = Engine(BinaryFunction(self.ADDR, self.CODE, project))
        engine.analyze()

        assert len(engine.memory_accesses) == 1
        assert engine.memory_accesses[0] == MemoryAccess(0x3294C, Arg(0), 0x4, MemoryAccessType.LOAD)

    def test_free_called_with_loaded_pointer(self):
        project = Project("ARM:LE:32:v7")
        engine = Engine(BinaryFunction(self.ADDR, self.CODE, project))
        engine.analyze()

        assert len(engine.callsites) == 1
        cs = engine.callsites[0]
        assert cs.target == self.FREE
        # arg0 of free is the deref of the spilled-and-reloaded original a0
        assert cs.args[0] == MemoryAccess(0x3294C, Arg(0), 0x4, MemoryAccessType.LOAD)

    def test_stack_spill_value_at_var_8(self):
        # STR R0, [R11, #-4] spills arg0 to a stack slot. Verify the engine tracks this
        # in instructions_state, not as a memory access.
        project = Project("ARM:LE:32:v7")
        engine = Engine(BinaryFunction(self.ADDR, self.CODE, project))
        engine.analyze()

        # The STR is at 0x32944; the value Arg(0) should be stored somewhere on the stack.
        state = engine.instructions_state[0x32944]
        assert Arg(0) in state.stack.values()


class TestARMLoopWithByteLoad:
    # ltrace binary `__hash_string`:
    #   v1 = 0;
    #   while ((c = ((unsigned char *)a0)[v1])) {
    #       v2 = c + 16 * v2;
    #       if (v2 & 0xF0000000) v2 ^= v2 & 0xF0000000 ^ ((v2 & 0xF0000000) >> 24);
    #       ++v1;
    #   }
    #   return v2;
    # Has a real loop with byte loads (LDRB) and ARM conditional execution (EORNE).
    CODE = b"\x00\x30\xa0\xe3\x03\x20\xa0\xe1\x04\x00\x00\xea\x02\x22\x81\xe0\x0f\x12\x12\xe2\x02\x20\x21\x10\x21\x2c\x22\x10\x01\x30\x83\xe2\x03\x10\xd0\xe7\x00\x00\x51\xe3\xf7\xff\xff\x1a\x02\x00\xa0\xe1\x1e\xff\x2f\xe1"
    ADDR = 0x455C4

    def test_loop_detected(self):
        project = Project("ARM:LE:32:v7")
        bf = BinaryFunction(self.ADDR, self.CODE, project)
        assert len(bf.loops_dict_start_address) == 1
        assert 0x455E4 in bf.loops_dict_start_address

    def test_loop_has_only_real_exit_condition(self):
        # The body has two EORNE (ARM conditional execution); those must NOT show up
        # as loop exit conditions. Only the BNE at the loop tail (0x455ec) is a real exit.
        project = Project("ARM:LE:32:v7")
        engine = Engine(BinaryFunction(self.ADDR, self.CODE, project))
        engine.analyze()

        loop = engine.loops_dict_start_address[0x455E4][0]
        assert set(loop.exit_conditions.keys()) == {0x455EC}

    def test_byte_load_uses_loop_counter(self):
        # The loop loads bytes from (arg0 + R3) where R3 is the loop induction variable.
        # The Register stamp should be at the loop header (0x455e4), where the engine
        # first reads R3 after clearing it for loop analysis.
        project = Project("ARM:LE:32:v7")
        engine = Engine(BinaryFunction(self.ADDR, self.CODE, project))
        engine.analyze()

        loop_counter = Register(0x2C, 0x455E4, project)  # R3 offset = 0x2c
        assert MemoryAccess(0x455E4, Arg(0), loop_counter, MemoryAccessType.LOAD) in engine.memory_accesses

    def test_conditional_execution_in_loop_body(self):
        # 2 EORNE instructions create 2 conditional sites inside the loop body.
        # Plus the BNE at the loop tail = 3 total.
        project = Project("ARM:LE:32:v7")
        engine = Engine(BinaryFunction(self.ADDR, self.CODE, project))
        engine.analyze()
        assert len(engine.conditional_sites) == 3


class TestARMBitManipulation:
    # ltrace binary `arm_branch_dest`:
    #   return a0 + 4 * ((a1 & 0xFFFFFF ^ 0x800000) - 0x800000) + 8;
    # Sign-extends a 24-bit ARM branch offset to 32 bits using BIC/EOR/SUB/LSL/ADD.
    # Spills both args to the stack frame via R11, then reloads them.
    CODE = b"\x04\xb0\x2d\xe5\x00\xb0\x8d\xe2\x0c\xd0\x4d\xe2\x08\x00\x0b\xe5\x0c\x10\x0b\xe5\x0c\x30\x1b\xe5\xff\x34\xc3\xe3\x02\x35\x23\xe2\x02\x35\x43\xe2\x03\x31\xa0\xe1\x08\x30\x83\xe2\x08\x20\x1b\xe5\x03\x30\x82\xe0\x03\x00\xa0\xe1\x00\xd0\x8b\xe2\x00\x08\xbd\xe8\x1e\xff\x2f\xe1"
    ADDR = 0x154F0

    def test_no_memory_accesses(self):
        # All STR/LDR are stack-frame spill/reload through R11. The engine should
        # resolve them all into stack slots, leaving no real memory accesses.
        project = Project("ARM:LE:32:v7")
        engine = Engine(BinaryFunction(self.ADDR, self.CODE, project))
        engine.analyze()
        assert engine.memory_accesses == []

    def test_return_value_is_sign_extension_expression(self):
        project = Project("ARM:LE:32:v7")
        engine = Engine(BinaryFunction(self.ADDR, self.CODE, project))
        engine.analyze()

        # Build the expected expression bottom-up:
        #   (((arg1 & ~0xff000000) ^ 0x800000) - 0x800000) << 2) + 8) + arg0
        masked = BinaryOp(Arg(1), UnaryOp(0xFF000000, "~"), "&")
        xored = BinaryOp(masked, 0x800000, "^")
        subbed = BinaryOp(xored, 0x800000, "-")
        shifted = BinaryOp(subbed, 2, "<<")
        with_offset = BinaryOp(shifted, 8, "+")
        expected = BinaryOp(Arg(0), with_offset, "+")
        assert engine.return_values == {expected}


class TestARMGlobalConditionalInit:
    # ltrace binary `expr_self`:
    #   if (!nodep_3071) { expr_init_self(&node_3072); nodep_3071 = (int)&node_3072; }
    #   return nodep_3071;
    # Exercises PC-relative literal loads, conditional initialisation, global stores.
    CODE = b"\x00\x48\x2d\xe9\x04\xb0\x8d\xe2\x34\x30\x9f\xe5\x00\x30\x93\xe5\x00\x00\x53\xe3\x04\x00\x00\x1a\x28\x00\x9f\xe5\x71\xfc\xff\xeb\x1c\x30\x9f\xe5\x1c\x20\x9f\xe5\x00\x20\x83\xe5\x10\x30\x9f\xe5\x00\x30\x93\xe5\x03\x00\xa0\xe1\x04\xd0\x4b\xe2\x00\x48\xbd\xe8\x1e\xff\x2f\xe1"
    ADDR = 0x2E9E0
    EXPR_INIT_SELF = 0x2DBC8
    NODEP_LITERAL = 0x2EA24  # PC-relative literal pool entry containing &nodep_3071
    NODE_LITERAL = 0x2EA28   # ... containing &node_3072

    def test_conditional_site_guards_init(self):
        project = Project("ARM:LE:32:v7")
        engine = Engine(BinaryFunction(self.ADDR, self.CODE, project))
        engine.analyze()
        # The BNE at 0x2e9f4 checks "is the global already initialised?" and skips the init.
        assert len(engine.conditional_sites) == 1
        cs = engine.conditional_sites[0]
        assert cs.addr == 0x2E9F4
        # Condition: deref the literal pool entry to get &nodep_3071, deref again to read it.
        assert cs.condition == BinaryOp(UnaryOp(UnaryOp(self.NODEP_LITERAL, "*"), "*"), 0, "!=")

    def test_init_callsite(self):
        project = Project("ARM:LE:32:v7")
        engine = Engine(BinaryFunction(self.ADDR, self.CODE, project))
        engine.analyze()

        assert len(engine.callsites) == 1
        cs = engine.callsites[0]
        assert cs.target == self.EXPR_INIT_SELF
        # arg0 is &node_3072 — loaded from the literal pool entry at NODE_LITERAL
        assert cs.args[0] == UnaryOp(self.NODE_LITERAL, "*")

    def test_global_store_writes_node_pointer(self):
        project = Project("ARM:LE:32:v7")
        engine = Engine(BinaryFunction(self.ADDR, self.CODE, project))
        engine.analyze()

        # *(*(NODEP_LITERAL)) = *(NODE_LITERAL)
        # i.e., store &node_3072 into the global pointer nodep_3071.
        stores = [ma for ma in engine.memory_accesses if ma.access_type == MemoryAccessType.STORE]
        assert len(stores) == 1
        assert stores[0].stored_value == UnaryOp(self.NODE_LITERAL, "*")

    def test_returns_global_pointer_value(self):
        project = Project("ARM:LE:32:v7")
        engine = Engine(BinaryFunction(self.ADDR, self.CODE, project))
        engine.analyze()

        # Final return: deref the literal pool to get &nodep_3071, then deref that to read its value.
        assert engine.return_values == {UnaryOp(UnaryOp(self.NODEP_LITERAL, "*"), "*")}


class TestARMTwoCallsWithStackReload:
    # ltrace binary `destroy_breakpoint_cb`:
    #   breakpoint_destroy(a1); free(a1); return 1;
    # Spills arg0..arg2 then reloads arg1 for both calls.
    CODE = b"\x00\x48\x2d\xe9\x04\xb0\x8d\xe2\x10\xd0\x4d\xe2\x08\x00\x0b\xe5\x0c\x10\x0b\xe5\x10\x20\x0b\xe5\x0c\x00\x1b\xe5\xf9\x4a\x00\xeb\x0c\x00\x1b\xe5\x16\x54\x01\xeb\x01\x30\xa0\xe3\x03\x00\xa0\xe1\x04\xd0\x4b\xe2\x00\x48\xbd\xe8\x1e\xff\x2f\xe1"
    ADDR = 0xA98C
    BREAKPOINT_DESTROY = 0x1D594
    FREE = 0x5FA10

    def test_two_callsites_to_correct_targets(self):
        project = Project("ARM:LE:32:v7")
        engine = Engine(BinaryFunction(self.ADDR, self.CODE, project))
        engine.analyze()

        assert len(engine.callsites) == 2
        assert engine.callsites[0].target == self.BREAKPOINT_DESTROY
        assert engine.callsites[1].target == self.FREE

    def test_first_argument_of_both_calls_is_arg1(self):
        # R0 is reloaded from the stack-spilled arg1 before each call.
        project = Project("ARM:LE:32:v7")
        engine = Engine(BinaryFunction(self.ADDR, self.CODE, project))
        engine.analyze()

        assert engine.callsites[0].args[0] == Arg(1)
        assert engine.callsites[1].args[0] == Arg(1)

    def test_returns_one(self):
        project = Project("ARM:LE:32:v7")
        engine = Engine(BinaryFunction(self.ADDR, self.CODE, project))
        engine.analyze()
        assert engine.return_values == {1}

    def test_no_real_memory_accesses(self):
        # Everything is stack-resolved; no actual memory_accesses should remain.
        project = Project("ARM:LE:32:v7")
        engine = Engine(BinaryFunction(self.ADDR, self.CODE, project))
        engine.analyze()
        assert engine.memory_accesses == []


class TestARMCompositeBoolean:
    # ltrace binary `execve`: SVC syscall + CMN R0, #0x1000 + MOVLS/BHI error path.
    # The post-CMN condition lifts to a BOOL_AND of (CY) and (!(R0+0x1000 == 0)), and
    # the conditional MOVLS uses a BOOL_NEGATE of that — exercising composite booleans.
    CODE = b"\x80\x40\x2d\xe9\x0b\x70\xa0\xe3\x00\x00\x00\xef\x01\x0a\x70\xe3\x00\x30\xa0\xe1\x00\x00\xa0\x91\x01\x00\x00\x8a\x80\x40\xbd\xe8\x1e\xff\x2f\xe1\x14\x20\x9f\xe5\x6c\x89\xfe\xeb\x02\x20\x9f\xe7\x00\x30\x63\xe2\x02\x30\x80\xe7\x00\x00\xe0\xe3\xf6\xff\xff\xea"
    ADDR = 0x9C8B0

    def test_function_analyses_without_crashing(self):
        # Before the fix, BOOL_NEGATE on a BOOL_AND result raised
        # "Cannot negate binary operation with operator '&'".
        project = Project("ARM:LE:32:v7")
        engine = Engine(BinaryFunction(self.ADDR, self.CODE, project))
        engine.analyze()
        # Should reach this point and have a meaningful analysis.
        assert len(engine.callsites) >= 1
        assert len(engine.conditional_sites) >= 1

    def test_two_return_paths(self):
        # Normal: syscall result. Error: -1 (lifted as ~0).
        project = Project("ARM:LE:32:v7")
        engine = Engine(BinaryFunction(self.ADDR, self.CODE, project))
        engine.analyze()
        # The error path stores -1; the success path passes through R0.
        # ~0 (0xFFFFFFFF == -1) should be one of the returns.
        assert UnaryOp(0, "~") in engine.return_values


class TestARMPointerArithmeticCall:
    # ltrace binary `type_init_struct`:
    #   type_init_common(a0, 11);
    #   return vect_init(a0 + 4, 8);
    # Exercises a tail-call where the first arg is computed by pointer arithmetic.
    CODE = b"\x00\x48\x2d\xe9\x04\xb0\x8d\xe2\x08\xd0\x4d\xe2\x08\x00\x0b\xe5\x08\x00\x1b\xe5\x0b\x10\xa0\xe3\xe7\xff\xff\xeb\x08\x30\x1b\xe5\x04\x30\x83\xe2\x03\x00\xa0\xe1\x08\x10\xa0\xe3\xb9\x93\xff\xeb\x04\xd0\x4b\xe2\x00\x48\xbd\xe8\x1e\xff\x2f\xe1"
    ADDR = 0x2B2F4
    TYPE_INIT_COMMON = 0x2B2B0
    VECT_INIT = 0x1020C

    def test_first_call_is_type_init_common(self):
        project = Project("ARM:LE:32:v7")
        engine = Engine(BinaryFunction(self.ADDR, self.CODE, project))
        engine.analyze()
        cs = engine.callsites[0]
        assert cs.target == self.TYPE_INIT_COMMON
        assert cs.args[0] == Arg(0)
        assert cs.args[1] == 11

    def test_tail_call_uses_offset_pointer(self):
        # vect_init's first arg is a0+4 (computed by ADD R3, R3, #4 after stack reload).
        project = Project("ARM:LE:32:v7")
        engine = Engine(BinaryFunction(self.ADDR, self.CODE, project))
        engine.analyze()
        cs = engine.callsites[1]
        assert cs.target == self.VECT_INIT
        assert cs.args[0] == BinaryOp(Arg(0), 4, "+")
        assert cs.args[1] == 8

    def test_returns_tail_call(self):
        project = Project("ARM:LE:32:v7")
        engine = Engine(BinaryFunction(self.ADDR, self.CODE, project))
        engine.analyze()
        # The function returns the result of vect_init (tail call)
        ret = next(iter(engine.return_values))
        assert isinstance(ret, CallSite)
        assert ret.target == self.VECT_INIT


class TestARMBooleanReturn:
    # ltrace binary `library_with_key_cb`:
    #   return *(_DWORD *)(a1 + 4) != *a2;
    # Lifts as MOVEQ/MOVNE pair on the same CMP result — nested ConditionalExpressions.
    CODE = b"\x04\xb0\x2d\xe5\x00\xb0\x8d\xe2\x14\xd0\x4d\xe2\x08\x00\x0b\xe5\x0c\x10\x0b\xe5\x10\x20\x0b\xe5\x0c\x30\x1b\xe5\x04\x20\x93\xe5\x10\x30\x1b\xe5\x00\x30\x93\xe5\x03\x00\x52\xe1\x00\x30\xa0\x03\x01\x30\xa0\x13\x03\x00\xa0\xe1\x00\xd0\x8b\xe2\x00\x08\xbd\xe8\x1e\xff\x2f\xe1"
    ADDR = 0xE960

    def test_loads_both_struct_fields(self):
        project = Project("ARM:LE:32:v7")
        engine = Engine(BinaryFunction(self.ADDR, self.CODE, project))
        engine.analyze()
        assert MemoryAccess(0xE97C, Arg(1), 0x4, MemoryAccessType.LOAD) in engine.memory_accesses
        assert MemoryAccess(0xE984, Arg(2), 0, MemoryAccessType.LOAD) in engine.memory_accesses

    def test_two_conditional_moves_create_two_sites(self):
        # MOVEQ R3, #0 followed by MOVNE R3, #1 on the same CMP
        project = Project("ARM:LE:32:v7")
        engine = Engine(BinaryFunction(self.ADDR, self.CODE, project))
        engine.analyze()
        assert len(engine.conditional_sites) == 2

    def test_returns_include_both_boolean_constants(self):
        # The MOVEQ→MOVNE chain produces nested ConditionalExpressions whose
        # collect_values yields both boolean constants. (The intermediate "leftover"
        # value from MOVEQ's NE branch is unreachable in practice but appears here
        # because the engine doesn't reason about inverse-condition correlation.)
        project = Project("ARM:LE:32:v7")
        engine = Engine(BinaryFunction(self.ADDR, self.CODE, project))
        engine.analyze()
        assert 0 in engine.return_values
        assert 1 in engine.return_values


class TestARMLinkedListLoop:
    # ltrace binary `slist_chase_end`:
    #   while (*a0) a0 = *(_DWORD **)a0;
    #   return a0;
    # Two-block loop walking a linked list — exits when the deref is NULL.
    CODE = b"\x04\xb0\x2d\xe5\x00\xb0\x8d\xe2\x0c\xd0\x4d\xe2\x08\x00\x0b\xe5\x02\x00\x00\xea\x08\x30\x1b\xe5\x00\x30\x93\xe5\x08\x30\x0b\xe5\x08\x30\x1b\xe5\x00\x30\x93\xe5\x00\x00\x53\xe3\xf8\xff\xff\x1a\x08\x30\x1b\xe5\x03\x00\xa0\xe1\x00\xd0\x8b\xe2\x00\x08\xbd\xe8\x1e\xff\x2f\xe1"
    ADDR = 0x96A8

    def test_loop_detected(self):
        project = Project("ARM:LE:32:v7")
        bf = BinaryFunction(self.ADDR, self.CODE, project)
        assert len(bf.loops_dict_start_address) == 1
        loop = bf.loops_dict_start_address[0x96C8][0]
        assert loop.blocks == {0x96C8, 0x96BC}

    def test_loop_exit_condition_at_bne(self):
        project = Project("ARM:LE:32:v7")
        engine = Engine(BinaryFunction(self.ADDR, self.CODE, project))
        engine.analyze()

        loop = engine.loops_dict_start_address[0x96C8][0]
        assert set(loop.exit_conditions.keys()) == {0x96D4}
        # Loop exits when the dereferenced pointer is NULL
        exit_cond = loop.exit_conditions[0x96D4]
        # Exit condition compares the loaded value with 0
        assert isinstance(exit_cond, BinaryOp)
        assert exit_cond.op == "=="
        assert exit_cond.right == 0

    def test_conditional_site_at_loop_tail(self):
        project = Project("ARM:LE:32:v7")
        engine = Engine(BinaryFunction(self.ADDR, self.CODE, project))
        engine.analyze()
        # Just one conditional site: the BNE at 0x96d4 driving the loop back-edge
        assert len(engine.conditional_sites) == 1
        cs = engine.conditional_sites[0]
        assert cs.addr == 0x96D4
        assert cs.iftrue == 0x96BC  # back to loop body
        assert cs.iffalse == 0x96D8  # exit
