from frozendict import frozendict

from binary_function import BinaryFunction
from engine_types import (
    Arg,
    BinaryOp,
    CallSite,
    MemoryAccess,
    MemoryAccessType,
    Register,
)
from pcode_engine import Engine
from project import Project

# All fixtures are real functions from the sshd MIPS:BE:32 binary.


class TestMIPSConditionalEarlyReturnWithCall:
    # sshd `BN_num_bits`:
    #   n = a0[1];
    #   if (!n) return 0;
    #   return 32 * (n - 1) + BN_num_bits_word(*(a0[0] + 4 * (n - 1)));
    # Exercises a BEQ early-return, a JAL in a delay slot, and a return value that
    # sums a shifted expression with a callsite result.
    CODE = b"\x8c\x82\x00\x04\x10\x40\x00\x0f\x00\x00\x00\x00\x27\xbd\xff\xe0\xaf\xb0\x00\x18\x24\x50\xff\xff\x8c\x82\x00\x00\x00\x10\x18\x80\xaf\xbf\x00\x1c\x00\x10\x81\x40\x00\x43\x10\x21\x0c\x11\xe5\xda\x8c\x44\x00\x00\x02\x02\x10\x21\x8f\xbf\x00\x1c\x8f\xb0\x00\x18\x27\xbd\x00\x20\x03\xe0\x00\x08\x00\x00\x00\x00"
    ADDR = 0x4797D8
    BN_NUM_BITS_WORD = 0x479768

    def test_conditional_site_guards_zero_path(self):
        project = Project(language="MIPS:BE:32:default")
        engine = Engine(BinaryFunction(self.ADDR, self.CODE))
        engine.analyze()

        assert len(engine.conditional_sites) == 1
        cs = engine.conditional_sites[0]
        assert cs.addr == 0x4797DC
        # n == 0 where n = *(a0 + 4)
        assert cs.condition == BinaryOp(MemoryAccess(0x4797D8, Arg(0), 0x4, MemoryAccessType.LOAD), 0, "==")

    def test_callsite_argument_double_deref(self):
        # BN_num_bits_word(*(a0[0] + 4 * (n - 1)))  where n = a0[1].
        # n - 1 is lifted as n + 0xFFFFFFFF (two's complement) then << 2.
        project = Project(language="MIPS:BE:32:default")
        engine = Engine(BinaryFunction(self.ADDR, self.CODE))
        engine.analyze()

        assert len(engine.callsites) == 1
        cs = engine.callsites[0]
        assert cs.target == self.BN_NUM_BITS_WORD

        n = MemoryAccess(0x4797D8, Arg(0), 0x4, MemoryAccessType.LOAD)
        n_minus_1 = BinaryOp(n, 0xFFFFFFFF, "+")
        a0_0 = MemoryAccess(0x4797F0, Arg(0), 0, MemoryAccessType.LOAD)
        # The address a0[0] + 4*(n-1) is split into base=*(arg0), offset=(n-1)<<2.
        assert cs.args[0] == MemoryAccess(0x479804, a0_0, BinaryOp(n_minus_1, 2, "<<"), MemoryAccessType.LOAD)

    def test_return_values(self):
        project = Project(language="MIPS:BE:32:default")
        engine = Engine(BinaryFunction(self.ADDR, self.CODE))
        engine.analyze()

        n = MemoryAccess(0x4797D8, Arg(0), 0x4, MemoryAccessType.LOAD)
        # Zero path: returns n (which is 0 there).
        assert n in engine.return_values
        # Non-zero path: 32*(n-1) + BN_num_bits_word(...) — one of the returns is
        # a BinaryOp summing a left-shift with the callsite.
        non_zero = next(r for r in engine.return_values if isinstance(r, BinaryOp))
        assert non_zero.op == "+"
        assert non_zero.left == BinaryOp(BinaryOp(n, 0xFFFFFFFF, "+"), 5, "<<")
        assert isinstance(non_zero.right, CallSite)
        assert non_zero.right.target == self.BN_NUM_BITS_WORD


class TestMIPSCallThenConditional:
    # sshd `sshbuf_len`:
    #   if (sshbuf_check_sanity()) return 0;
    #   return *(a0 + 12) - *(a0 + 8);
    CODE = b"\x27\xbd\xff\xe0\xaf\xb0\x00\x18\xaf\xbf\x00\x1c\x0c\x10\xa1\x49\x00\x80\x80\x21\x14\x40\x00\x04\x00\x00\x18\x21\x8e\x02\x00\x0c\x8e\x03\x00\x08\x00\x43\x18\x23\x8f\xbf\x00\x1c\x00\x60\x10\x21\x8f\xb0\x00\x18\x03\xe0\x00\x08\x27\xbd\x00\x20"
    ADDR = 0x428B24
    CHECK_SANITY = 0x428524

    def test_single_callsite(self):
        project = Project(language="MIPS:BE:32:default")
        engine = Engine(BinaryFunction(self.ADDR, self.CODE))
        engine.analyze()
        assert len(engine.callsites) == 1
        assert engine.callsites[0].target == self.CHECK_SANITY

    def test_conditional_on_call_result(self):
        # BNE on the callsite return value (sanity check failed -> return 0).
        project = Project(language="MIPS:BE:32:default")
        engine = Engine(BinaryFunction(self.ADDR, self.CODE))
        engine.analyze()
        cs = engine.conditional_sites[0]
        assert isinstance(cs.condition, BinaryOp)
        assert cs.condition.op == "!="
        assert isinstance(cs.condition.left, CallSite)
        assert cs.condition.left.target == self.CHECK_SANITY
        assert cs.condition.right == 0

    def test_memory_accesses_and_return(self):
        project = Project(language="MIPS:BE:32:default")
        engine = Engine(BinaryFunction(self.ADDR, self.CODE))
        engine.analyze()

        hi = MemoryAccess(0x428B40, Arg(0), 0xC, MemoryAccessType.LOAD)
        lo = MemoryAccess(0x428B44, Arg(0), 0x8, MemoryAccessType.LOAD)
        assert hi in engine.memory_accesses
        assert lo in engine.memory_accesses
        # Two return paths: 0 (sanity failed) and the length difference.
        assert 0 in engine.return_values
        assert BinaryOp(hi, lo, "-") in engine.return_values


class TestMIPSVarargs:
    # sshd `error`:  return do_log(2, fmt, &va, ...);
    # The R1..R3 register args are spilled to the stack so they can be read as a
    # va_list, and a pointer to that area is passed as the 3rd argument.
    CODE = b"\x27\xbd\xff\xd8\xaf\xa6\x00\x30\x27\xa6\x00\x2c\xaf\xa5\x00\x2c\x00\x80\x28\x21\x24\x04\x00\x02\xaf\xbf\x00\x24\xaf\xa7\x00\x34\x0c\x11\x0b\x4a\xaf\xa6\x00\x18\x8f\xbf\x00\x24\x03\xe0\x00\x08\x27\xbd\x00\x28"
    ADDR = 0x442FF8
    DO_LOG = 0x442D28

    def test_calls_do_log_with_level_2(self):
        project = Project(language="MIPS:BE:32:default")
        engine = Engine(BinaryFunction(self.ADDR, self.CODE))
        engine.analyze()

        assert len(engine.callsites) == 1
        cs = engine.callsites[0]
        assert cs.target == self.DO_LOG
        assert cs.args[0] == 2  # LOG level
        assert cs.args[1] == Arg(0)  # format string

    def test_va_list_pointer_is_stack_relative(self):
        project = Project(language="MIPS:BE:32:default")
        engine = Engine(BinaryFunction(self.ADDR, self.CODE))
        engine.analyze()
        cs = engine.callsites[0]
        # arg2 is &va — a pointer into the spilled-register area on the stack.
        assert isinstance(cs.args[2], BinaryOp)
        assert cs.args[2].op == "+"
        assert isinstance(cs.args[2].left, Register)
        assert isinstance(cs.args[2].right, int)


class TestMIPSNestedLoop:
    # sshd `strspn`: returns the length of the prefix of a0 made entirely of
    # bytes present in a1.
    #   v1 = a0;
    #   while (*v1) {
    #       a2 = a1;
    #       while (*a2) { if (*v1 == *a2) { ++v1; goto outer; } ++a2; }
    #       break;
    #   }
    #   return v1 - a0;
    # An inner loop fully contained in an outer loop.
    CODE = b"\x00\x80\x18\x21\x90\x67\x00\x00\x10\xe0\x00\x09\x00\x64\x10\x23\x00\xa0\x30\x21\x90\xc8\x00\x00\x11\x00\x00\x05\x00\x00\x00\x00\x14\xe8\xff\xfc\x24\xc6\x00\x01\x10\x00\xff\xf6\x24\x63\x00\x01\x03\xe0\x00\x08\x00\x00\x00\x00\x00\x00\x00\x00"
    ADDR = 0x562570

    def test_two_loops_detected(self):
        project = Project(language="MIPS:BE:32:default")
        bf = BinaryFunction(self.ADDR, self.CODE)
        # Inner loop at 0x562584, outer loop at 0x562574.
        assert set(bf.loops_dict_start_address.keys()) == {0x562584, 0x562574}

    def test_inner_loop_nested_in_outer(self):
        # The outer loop's block set contains the inner loop's blocks.
        project = Project(language="MIPS:BE:32:default")
        bf = BinaryFunction(self.ADDR, self.CODE)
        inner = bf.loops_dict_start_address[0x562584][0]
        outer = bf.loops_dict_start_address[0x562574][0]
        assert inner.blocks == {0x562584, 0x562590}
        assert inner.blocks <= outer.blocks
        assert 0x562574 in outer.blocks

    def test_byte_loads_from_both_pointers(self):
        # Outer walks a0 (via v1), inner walks a1 (via a2). Both produce byte loads
        # using fresh loop-cleared base registers.
        project = Project(language="MIPS:BE:32:default")
        engine = Engine(BinaryFunction(self.ADDR, self.CODE))
        engine.analyze()
        loads = [ma for ma in engine.memory_accesses if ma.access_type == MemoryAccessType.LOAD]
        assert len(loads) == 2
        # The outer-pointer byte and inner-pointer byte are compared at 0x562590.
        v1 = Register(12, 0x562574)  # $v1
        a2 = Register(24, 0x562584)  # $a2
        assert MemoryAccess(0x562574, v1, 0, MemoryAccessType.LOAD) in loads
        assert MemoryAccess(0x562584, a2, 0, MemoryAccessType.LOAD) in loads

    def test_exit_conditions(self):
        # Outer exits when *v1 == 0 (0x562578); inner exits when *a2 == 0 (0x562588).
        project = Project(language="MIPS:BE:32:default")
        engine = Engine(BinaryFunction(self.ADDR, self.CODE))
        engine.analyze()

        outer = engine.loops_dict_start_address[0x562574][0]
        inner = engine.loops_dict_start_address[0x562584][0]
        assert 0x562578 in outer.exit_conditions
        assert 0x562588 in inner.exit_conditions

    def test_return_is_pointer_difference(self):
        project = Project(language="MIPS:BE:32:default")
        engine = Engine(BinaryFunction(self.ADDR, self.CODE))
        engine.analyze()
        # return v1 - a0, where v1 is the loop-advanced pointer.
        ret = next(iter(engine.return_values))
        assert isinstance(ret, BinaryOp)
        assert ret.op == "-"
        assert ret.right == Arg(0)
