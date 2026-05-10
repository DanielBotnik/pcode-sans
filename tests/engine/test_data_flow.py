from frozendict import frozendict
from binary_function import BinaryFunction
from engine_types import Arg, BinaryOp, CallSite, ConditionalSite, Loop, MemoryAccess, MemoryAccessType, Register
from pcode_engine import Engine
from project import Project


class TestDoubleDeref:
    def test_double_deref_memory_accesses(self):
        # sshd binary `pmeth_cmp` function: return **a0 - **a1
        CODE = b"\x8c\x83\x00\x00\x8c\xa2\x00\x00\x8c\x63\x00\x00\x8c\x42\x00\x00\x03\xe0\x00\x08\x00\x62\x10\x23"
        ADDR = 0x00496400

        project = Project("MIPS:BE:32:default")
        engine = Engine(BinaryFunction(ADDR, CODE, project))
        engine.analyze()

        outer_a0 = MemoryAccess(0x00496400, Arg(0), 0, MemoryAccessType.LOAD)
        outer_a1 = MemoryAccess(0x00496404, Arg(1), 0, MemoryAccessType.LOAD)
        inner_a0 = MemoryAccess(0x00496408, outer_a0, 0, MemoryAccessType.LOAD)
        inner_a1 = MemoryAccess(0x0049640C, outer_a1, 0, MemoryAccessType.LOAD)

        assert len(engine.memory_accesses) == 4
        assert outer_a0 in engine.memory_accesses
        assert outer_a1 in engine.memory_accesses
        assert inner_a0 in engine.memory_accesses
        assert inner_a1 in engine.memory_accesses

    def test_double_deref_return_value(self):
        # sshd binary `pmeth_cmp` function: return **a0 - **a1
        CODE = b"\x8c\x83\x00\x00\x8c\xa2\x00\x00\x8c\x63\x00\x00\x8c\x42\x00\x00\x03\xe0\x00\x08\x00\x62\x10\x23"
        ADDR = 0x00496400

        project = Project("MIPS:BE:32:default")
        engine = Engine(BinaryFunction(ADDR, CODE, project))
        engine.analyze()

        outer_a0 = MemoryAccess(0x00496400, Arg(0), 0, MemoryAccessType.LOAD)
        outer_a1 = MemoryAccess(0x00496404, Arg(1), 0, MemoryAccessType.LOAD)
        inner_a0 = MemoryAccess(0x00496408, outer_a0, 0, MemoryAccessType.LOAD)
        inner_a1 = MemoryAccess(0x0049640C, outer_a1, 0, MemoryAccessType.LOAD)

        assert engine.return_values == {BinaryOp(inner_a0, inner_a1, "-")}


class TestTailCallWithConditional:
    def test_sshkey_is_cert_callsites(self):
        # sshd binary `sshkey_is_cert`: if (!a0) return 0; else return sshkey_type_is_cert(*a0)
        CODE = b"\x10\x80\x00\x03\x00\x00\x00\x00\x08\x10\xa4\xa5\x8c\x84\x00\x00\x03\xe0\x00\x08\x00\x00\x10\x21"
        ADDR = 0x00429708

        project = Project("MIPS:BE:32:default")
        engine = Engine(BinaryFunction(ADDR, CODE, project))
        engine.analyze()

        deref_a0 = MemoryAccess(0x00429710, Arg(0), 0, MemoryAccessType.LOAD)
        expected_callsite = CallSite(0x00429710, 0x00429294, frozendict({0: deref_a0}))

        assert len(engine.callsites) == 1
        assert engine.callsites[0] == expected_callsite

    def test_sshkey_is_cert_return_values(self):
        # sshd binary `sshkey_is_cert`: returns 0 (null path) or the tail-called result
        CODE = b"\x10\x80\x00\x03\x00\x00\x00\x00\x08\x10\xa4\xa5\x8c\x84\x00\x00\x03\xe0\x00\x08\x00\x00\x10\x21"
        ADDR = 0x00429708

        project = Project("MIPS:BE:32:default")
        engine = Engine(BinaryFunction(ADDR, CODE, project))
        engine.analyze()

        deref_a0 = MemoryAccess(0x00429710, Arg(0), 0, MemoryAccessType.LOAD)
        tail_call = CallSite(0x00429710, 0x00429294, frozendict({0: deref_a0}))

        assert engine.return_values == {0, tail_call}

    def test_sshkey_is_cert_memory_accesses(self):
        # The only memory access is the dereference of a0 before the tail call
        CODE = b"\x10\x80\x00\x03\x00\x00\x00\x00\x08\x10\xa4\xa5\x8c\x84\x00\x00\x03\xe0\x00\x08\x00\x00\x10\x21"
        ADDR = 0x00429708

        project = Project("MIPS:BE:32:default")
        engine = Engine(BinaryFunction(ADDR, CODE, project))
        engine.analyze()

        assert len(engine.memory_accesses) == 1
        assert engine.memory_accesses[0] == MemoryAccess(0x00429710, Arg(0), 0, MemoryAccessType.LOAD)

    def test_sshkey_is_cert_conditional_site(self):
        # beq $a0, $zero branches to the null return path; fall-through goes to tail call
        CODE = b"\x10\x80\x00\x03\x00\x00\x00\x00\x08\x10\xa4\xa5\x8c\x84\x00\x00\x03\xe0\x00\x08\x00\x00\x10\x21"
        ADDR = 0x00429708

        project = Project("MIPS:BE:32:default")
        engine = Engine(BinaryFunction(ADDR, CODE, project))
        engine.analyze()

        assert len(engine.conditional_sites) == 1
        cs = engine.conditional_sites[0]
        assert cs == ConditionalSite(
            addr=0x00429708,
            condition=BinaryOp(Arg(0), 0, "=="),
            iftrue=0x00429718,   # null path → returns 0
            iffalse=0x00429710,  # fall-through → tail call to sshkey_type_is_cert
        )


class TestLoopWithByteLoads:
    def test_timingsafe_bcmp_loop_structure(self):
        # sshd binary `timingsafe_bcmp`: XOR bytes from two buffers, return (OR != 0)
        CODE = b"\x00\x00\x18\x21\x00\x00\x10\x21\x10\x66\x00\x09\x00\xa3\x38\x21\x00\x83\x40\x21\x24\x63\x00\x01\x90\xe7\x00\x00\x91\x08\x00\x00\x00\xe8\x38\x26\x30\xe7\x00\xff\x08\x11\xd9\x7a\x00\x47\x10\x25\x03\xe0\x00\x08\x00\x02\x10\x2b"
        ADDR = 0x004765E0

        project = Project("MIPS:BE:32:default")
        engine = Engine(BinaryFunction(ADDR, CODE, project))
        engine.analyze()

        assert len(engine.loops_dict_start_address) == 1

        loop_counter = Register(12, 0x004765E8, project)  # $v1 cleared at loop header
        expected_loop = Loop(
            start=0x004765E8,
            blocks={0x004765E8, 0x004765F0},
            exit_conditions={0x004765E8: BinaryOp(loop_counter, Arg(2), "==")},
        )
        assert engine.loops_dict_start_address[0x004765E8] == [expected_loop]

    def test_timingsafe_bcmp_byte_load_memory_accesses(self):
        # lbu (byte load with INT_ZEXT) should produce MemoryAccess entries with loop variable offset
        CODE = b"\x00\x00\x18\x21\x00\x00\x10\x21\x10\x66\x00\x09\x00\xa3\x38\x21\x00\x83\x40\x21\x24\x63\x00\x01\x90\xe7\x00\x00\x91\x08\x00\x00\x00\xe8\x38\x26\x30\xe7\x00\xff\x08\x11\xd9\x7a\x00\x47\x10\x25\x03\xe0\x00\x08\x00\x02\x10\x2b"
        ADDR = 0x004765E0

        project = Project("MIPS:BE:32:default")
        engine = Engine(BinaryFunction(ADDR, CODE, project))
        engine.analyze()

        loop_counter = Register(12, 0x004765E8, project)

        assert MemoryAccess(0x004765F8, Arg(1), loop_counter, MemoryAccessType.LOAD) in engine.memory_accesses
        assert MemoryAccess(0x004765FC, Arg(0), loop_counter, MemoryAccessType.LOAD) in engine.memory_accesses

    def test_timingsafe_bcmp_return_value(self):
        # sltu $v0, $zero, $v0 in delay slot → return value is BinaryOp(0, or_accumulator, "<")
        CODE = b"\x00\x00\x18\x21\x00\x00\x10\x21\x10\x66\x00\x09\x00\xa3\x38\x21\x00\x83\x40\x21\x24\x63\x00\x01\x90\xe7\x00\x00\x91\x08\x00\x00\x00\xe8\x38\x26\x30\xe7\x00\xff\x08\x11\xd9\x7a\x00\x47\x10\x25\x03\xe0\x00\x08\x00\x02\x10\x2b"
        ADDR = 0x004765E0

        project = Project("MIPS:BE:32:default")
        engine = Engine(BinaryFunction(ADDR, CODE, project))
        engine.analyze()

        # $v0 is cleared at the loop header but not read there. The loop back-edge state is
        # filtered, so the exit block's entry state has no $v0. The first read of $v0 happens
        # at 0x476610 (the sltu delay slot), stamping the Register with that address.
        or_accumulator = Register(8, 0x00476610, project)
        assert engine.return_values == {BinaryOp(0, or_accumulator, "<")}
