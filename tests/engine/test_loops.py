from binary_function import BinaryFunction, Loop
from pcode_engine import Engine
from project import Project
from engine_types import Arg, BinaryOp, MemoryAccess, MemoryAccessType, Register


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
        assert bin_func.loops_dict_start_address[0x43F934] == expected_loop

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

        assert bin_func.loops_dict_start_address[0x0046FAF8] == expected_loop

    def test_func_start_with_loop_doesnt_visit_block_twice(self):
        # sshd binary `crypto_sign_ed25519_ref_fe25519_add` function
        CODE = b"\x00\x00\x10!$\x07\x00\x80\x00\xc2\x18!\x00\xa2H!\x00\x82@!\x8cc\x00\x00$B\x00\x04\x8d)\x00\x00\x00i\x18!\x14G\xff\xf8\xad\x03\x00\x00\x08\x11\xbd\xbc\x00\x00\x00\x00"
        ADDR = 0x0046FAF0

        project = Project("MIPS:BE:32:default")
        bin_func = BinaryFunction(ADDR, CODE, project)

        blocks = list(bin_func.code_flow_grpah.traverse())
        assert len(blocks) == len(set(blocks))
