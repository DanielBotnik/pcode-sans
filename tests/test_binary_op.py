from engine_types import Arg
from pcode_engine import BinaryOp


class TestBinaryOp:

    def test_compression_equal_zero(self):
        reg = Arg(0)

        assert BinaryOp(reg, 0, "==") == BinaryOp.create_binop(Arg(0), 0, "==")

        assert BinaryOp(reg, 0, "!=") == BinaryOp.create_binop(BinaryOp(reg, 0, "=="), 0, "==")
        assert BinaryOp(reg, 0, "==") == BinaryOp.create_binop(BinaryOp(reg, 0, "!="), 0, "==")
        assert BinaryOp(reg, 0, ">=") == BinaryOp.create_binop(BinaryOp(reg, 0, "<"), 0, "==")
        assert BinaryOp(reg, 0, "<=") == BinaryOp.create_binop(BinaryOp(reg, 0, ">"), 0, "==")
        assert BinaryOp(reg, 0, ">") == BinaryOp.create_binop(BinaryOp(reg, 0, "<="), 0, "==")
        assert BinaryOp(reg, 0, "<") == BinaryOp.create_binop(BinaryOp(reg, 0, ">="), 0, "==")
