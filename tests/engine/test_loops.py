from binary_function import BinaryFunction, Loop
from pcode_engine import Engine
from project import Project
from engine_types import Arg, BinaryOp, MemoryAccess, MemoryAccessType, Register, UnaryOp


class TestLoops:
    def test_loop_sanity(self):
        CODE = b"<\x02\x00^$BY\xd4\x8cC\x00\x00P`\x00\x06\x00\x00\x10!\x8cC\x00\x04\x10d\x00\x03\x00\x00\x00\x00\x08\x10\xfeM$B\x00$\x03\xe0\x00\x08\x00\x00\x00\x00"
        ADDR = 0x0043F92C

        project = Project("MIPS:BE:32:default")
        bin_func = BinaryFunction(ADDR, CODE, project)
        engine = Engine(bin_func)

        base = Register(8, 0x43F934, bin_func)
        expected_loop = Loop(
            start=0x43F934,
            blocks={0x0043F934, 0x0043F940, 0x0043F94C},
            exit_conditions={
                0x43F938: BinaryOp(MemoryAccess(0x43F934, base, 0x0, MemoryAccessType.LOAD), 0x0, "=="),
                0x43F944: BinaryOp(MemoryAccess(0x43F934, base, 0x4, MemoryAccessType.LOAD), Arg(0), "=="),
            },
        )
        assert bin_func.loops_dict_start_address[0x43F934] == [expected_loop]

    def test_loop_with_gotos_to_exit(self):
        # sshd binary `crypto_sign_ed25519_ref_fe25519_add` function
        CODE = b"\x00\x00\x10!$\x07\x00\x80\x00\xc2\x18!\x00\xa2H!\x00\x82@!\x8cc\x00\x00$B\x00\x04\x8d)\x00\x00\x00i\x18!\x14G\xff\xf8\xad\x03\x00\x00\x08\x11\xbd\xbc\x00\x00\x00\x00"
        ADDR = 0x0046FAF0

        project = Project("MIPS:BE:32:default")
        bin_func = BinaryFunction(ADDR, CODE, project)
        engine = Engine(bin_func)

        assert len(bin_func.loops_dict_start_address) == 1

        expected_loop = Loop(
            start=0x0046FAF8,
            blocks={0x0046FAF8},
            exit_conditions={
                0x0046FB14: BinaryOp(BinaryOp(Register(8, 0x0046FAF8, bin_func), 4, "+"), 128, "=="),
            },
        )

        assert bin_func.loops_dict_start_address[0x0046FAF8] == [expected_loop]

    def test_func_start_with_loop_doesnt_visit_block_twice(self):
        # sshd binary `crypto_sign_ed25519_ref_fe25519_add` function
        CODE = b"\x00\x00\x10!$\x07\x00\x80\x00\xc2\x18!\x00\xa2H!\x00\x82@!\x8cc\x00\x00$B\x00\x04\x8d)\x00\x00\x00i\x18!\x14G\xff\xf8\xad\x03\x00\x00\x08\x11\xbd\xbc\x00\x00\x00\x00"
        ADDR = 0x0046FAF0

        project = Project("MIPS:BE:32:default")
        bin_func = BinaryFunction(ADDR, CODE, project)

        blocks = list(bin_func.code_flow_grpah.traverse())
        assert len(blocks) == len(set(blocks))

    def test_two_loops_from_same_block(self):
        # sshd binary `rawmemchr` function
        CODE = b"0\xa6\x00\xff0\x82\x00\x03P@\x00\x060\xa5\x00\xff\x90\x82\x00\x00\x10F\x00%\x00\x00\x00\x00\x10\x00\xff\xf9$\x84\x00\x01\x00\x05\x12\x00<\t\x81\x01\x00E(%\x00\x05\x14\x00<\x08~\xfe%)\x01\x00\x00E(%5\x08\xfe\xff$\x82\x00\x04\x8cC\xff\xfc\x00\xa3\x18&\x00\x038'\x00h\x18!\x00\xe3\x18&\x00i\x18$T`\x00\x03\x90C\xff\xfc\x10\x00\xff\xf6\x00@ !\x10f\x00\x0e\x00\x00\x00\x00\x90C\xff\xfdTf\x00\x03\x90C\xff\xfe\x03\xe0\x00\x08$\x82\x00\x01Tf\x00\x03\x90C\xff\xff\x03\xe0\x00\x08$\x82\x00\x02Tf\xff\xe9\x00@ !\x03\xe0\x00\x08$\x82\x00\x03\x03\xe0\x00\x08\x00\x80\x10!"
        ADDR = 0x00572EE0

        project = Project("MIPS:BE:32:default")
        bin_func = BinaryFunction(ADDR, CODE, project)
        engine = Engine(bin_func)

        assert len(bin_func.loops_dict_start_address) == 2

        single_loop = Loop(
            start=0x00572EE4,
            blocks={0x00572EE4, 0x00572EF0, 0x00572EFC},
            exit_conditions={
                0x00572EE8: BinaryOp(BinaryOp(Register(16, 0x00572EE4, bin_func), 3, "&"), 0, "=="),
                0x00572EF4: BinaryOp(
                    MemoryAccess(0x00572EF0, Register(16, 0x00572EE4, bin_func), 0, MemoryAccessType.LOAD),
                    BinaryOp(Arg(1), 0xFF, "&"),
                    "==",
                ),
            },
        )

        assert [single_loop] == bin_func.loops_dict_start_address[0x00572EE4]

        a1 = Register(20, 0x572EE8, bin_func)
        a1_lowbyte = BinaryOp(a1, 0xFF, "&")
        a1_shifted = BinaryOp(a1_lowbyte, 0x8, "<<")
        a1_ored = BinaryOp(a1_shifted, a1_lowbyte, "|")
        v3 = BinaryOp(BinaryOp(a1_ored, 0x10, "<<"), a1_ored, "|")
        v3_xor_a1 = BinaryOp(
            v3, MemoryAccess(0x00572F28, Register(16, 0x00572F24, bin_func), 0, MemoryAccessType.LOAD), "^"
        )
        full_expr = BinaryOp(
            BinaryOp(UnaryOp(v3_xor_a1, "~"), BinaryOp(v3_xor_a1, 0x7EFEFEFF, "+"), "^"),
            0x81010100,
            "&",
        )

        loop1 = Loop(
            start=0x00572F24,
            blocks={0x00572F24, 0x00572F48},
            exit_conditions={0x00572F40: BinaryOp(full_expr, 0, "!=")},
        )

        right_side = BinaryOp(Arg(1), 0xFF, "&")
        left_reg = Register(16, 0x00572F24, bin_func)

        loop2 = Loop(
            start=0x00572F24,
            blocks={0x00572F24, 0x00572F50, 0x00572F58, 0x00572F6C, 0x00572F7C},
            exit_conditions={
                0x00572F50: BinaryOp(MemoryAccess(0x00572F44, left_reg, 0, MemoryAccessType.LOAD), right_side, "=="),
                0x00572F5C: BinaryOp(MemoryAccess(0x00572F58, left_reg, 1, MemoryAccessType.LOAD), right_side, "=="),
                0x00572F6C: BinaryOp(MemoryAccess(0x00572F60, left_reg, 2, MemoryAccessType.LOAD), right_side, "=="),
                0x00572F7C: BinaryOp(MemoryAccess(0x00572F70, left_reg, 3, MemoryAccessType.LOAD), right_side, "=="),
            },
        )

        assert loop1 in bin_func.loops_dict_start_address[0x00572F24]
        assert loop2 in bin_func.loops_dict_start_address[0x00572F24]
