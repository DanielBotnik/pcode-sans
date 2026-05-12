from engine_types import Arg
from pcode_engine import BinaryOp


class TestCompressionBinaryOp:
    def test_compression_operations_sanity(self):
        assert BinaryOp(Arg(0), Arg(1), "==") == BinaryOp.create_binop(Arg(0), Arg(1), "==")
        assert BinaryOp(Arg(0), Arg(1), "!=") == BinaryOp.create_binop(Arg(0), Arg(1), "!=")
        assert BinaryOp(Arg(0), Arg(1), "<") == BinaryOp.create_binop(Arg(0), Arg(1), "<")
        assert BinaryOp(Arg(0), Arg(1), ">") == BinaryOp.create_binop(Arg(0), Arg(1), ">")
        assert BinaryOp(Arg(0), Arg(1), "<=") == BinaryOp.create_binop(Arg(0), Arg(1), "<=")
        assert BinaryOp(Arg(0), Arg(1), ">=") == BinaryOp.create_binop(Arg(0), Arg(1), ">=")

    def test_compression_equal_zero_sanity(self):
        assert BinaryOp(Arg(0), 0, "==") == BinaryOp.create_binop(Arg(0), 0, "==")

    def test_compression_equal_zero_negation(self):
        assert BinaryOp(Arg(0), 0, "!=") == BinaryOp.create_binop(BinaryOp(Arg(0), 0, "=="), 0, "==")
        assert BinaryOp(Arg(0), 0, "==") == BinaryOp.create_binop(BinaryOp(Arg(0), 0, "!="), 0, "==")
        assert BinaryOp(Arg(0), 0, ">=") == BinaryOp.create_binop(BinaryOp(Arg(0), 0, "<"), 0, "==")
        assert BinaryOp(Arg(0), 0, "<=") == BinaryOp.create_binop(BinaryOp(Arg(0), 0, ">"), 0, "==")
        assert BinaryOp(Arg(0), 0, ">") == BinaryOp.create_binop(BinaryOp(Arg(0), 0, "<="), 0, "==")
        assert BinaryOp(Arg(0), 0, "<") == BinaryOp.create_binop(BinaryOp(Arg(0), 0, ">="), 0, "==")

    def test_compression_equal_zero_between_integers(self):
        assert 0 == BinaryOp.create_binop(1, 0, "==")
        assert 1 == BinaryOp.create_binop(0, 0, "==")

    def test_compression_not_equal_zero_sanity(self):
        assert BinaryOp(Arg(0), 0, "!=") == BinaryOp.create_binop(Arg(0), 0, "!=")

    def test_compression_not_equal_zero_negation(self):
        assert BinaryOp(Arg(0), 0, "==") == BinaryOp.create_binop(BinaryOp(Arg(0), 0, "=="), 0, "!=")
        assert BinaryOp(Arg(0), 0, "!=") == BinaryOp.create_binop(BinaryOp(Arg(0), 0, "!="), 0, "!=")
        assert BinaryOp(Arg(0), 0, "<") == BinaryOp.create_binop(BinaryOp(Arg(0), 0, "<"), 0, "!=")
        assert BinaryOp(Arg(0), 0, ">") == BinaryOp.create_binop(BinaryOp(Arg(0), 0, ">"), 0, "!=")
        assert BinaryOp(Arg(0), 0, "<=") == BinaryOp.create_binop(BinaryOp(Arg(0), 0, "<="), 0, "!=")
        assert BinaryOp(Arg(0), 0, ">=") == BinaryOp.create_binop(BinaryOp(Arg(0), 0, ">="), 0, "!=")

    def test_compression_not_equal_zero_between_integers(self):
        assert 1 == BinaryOp.create_binop(1, 0, "!=")
        assert 0 == BinaryOp.create_binop(0, 0, "!=")

    def test_optimized_xor_less_than_one_unsigned(self):
        assert BinaryOp(Arg(0), Arg(1), "==") == BinaryOp.create_binop(
            BinaryOp(Arg(0), Arg(1), "^"), 1, "<", signed=False
        )


class TestArithmeticBinaryOp:
    def test_arithmetic_operations_sanity(self):
        assert BinaryOp(Arg(0), Arg(1), "+") == BinaryOp.create_binop(Arg(0), Arg(1), "+")
        assert BinaryOp(Arg(0), Arg(1), "-") == BinaryOp.create_binop(Arg(0), Arg(1), "-")

    def test_addition_with_zero(self):
        assert Arg(0) == BinaryOp.create_binop(Arg(0), 0, "+")

    def test_subtraction_with_zero(self):
        assert Arg(0) == BinaryOp.create_binop(Arg(0), 0, "-")

    def test_zero_minus_x_is_negation(self):
        # 0 - x is negation, not x (0 is not a left identity for subtraction)
        assert BinaryOp(0, Arg(0), "-") == BinaryOp.create_binop(0, Arg(0), "-")

    def test_associative_arithemtic_operations(self):
        assert BinaryOp(Arg(0), 5, "+") == BinaryOp.create_binop(BinaryOp(Arg(0), 2, "+"), 3, "+")
        assert BinaryOp(Arg(0), 6, "*") == BinaryOp.create_binop(BinaryOp(Arg(0), 2, "*"), 3, "*")

    def test_mixed_add_sub_folding(self):
        # (x + c1) - c2 → BinaryOp(x, c1-c2, "+")
        assert BinaryOp(Arg(0), 2, "+") == BinaryOp.create_binop(BinaryOp(Arg(0), 5, "+"), 3, "-")
        # (x - c1) - c2 → BinaryOp(x, -(c1+c2) & mask, "+")
        assert BinaryOp(Arg(0), (-8) & 0xFFFFFFFF, "+") == BinaryOp.create_binop(BinaryOp(Arg(0), 4, "-"), 4, "-")
        # (x - c1) + c2 where c2 > c1 → BinaryOp(x, c2-c1, "+")
        assert BinaryOp(Arg(0), 2, "+") == BinaryOp.create_binop(BinaryOp(Arg(0), 3, "-"), 5, "+")
        # (x + c1) - c1 → x (combined == 0)
        assert Arg(0) == BinaryOp.create_binop(BinaryOp(Arg(0), 4, "+"), 4, "-")

    def test_binary_op_plus_zero(self):
        # BinaryOp + 0 should return the BinaryOp unchanged
        inner = BinaryOp(Arg(0), Arg(1), "+")
        assert inner == BinaryOp.create_binop(inner, 0, "+")

    def test_binary_op_minus_zero(self):
        # BinaryOp - 0 should return the BinaryOp unchanged
        inner = BinaryOp(Arg(0), 4, "+")
        assert inner == BinaryOp.create_binop(inner, 0, "-")

    def test_sub_compared_with_zero_simplifies(self):
        # (a - b) == 0 → a == b and (a - b) != 0 → a != b
        # ARM's CMP lifts as INT_SUB, so this simplification cleans up
        # condition expressions where CMP feeds INT_EQUAL/INT_NOTEQUAL.
        assert BinaryOp(Arg(0), Arg(1), "==") == BinaryOp.create_binop(
            BinaryOp(Arg(0), Arg(1), "-"), 0, "=="
        )
        assert BinaryOp(Arg(0), Arg(1), "!=") == BinaryOp.create_binop(
            BinaryOp(Arg(0), Arg(1), "-"), 0, "!="
        )
        # Works with an int right-operand too
        assert BinaryOp(Arg(0), 5, "==") == BinaryOp.create_binop(
            BinaryOp(Arg(0), 5, "-"), 0, "=="
        )

    def test_arithmetic_operations_of_integers(self):
        assert 9 == BinaryOp.create_binop(5, 4, "+")
        assert 1 == BinaryOp.create_binop(5, 4, "-")
        assert 20 == BinaryOp.create_binop(5, 4, "*")
        assert 5 == BinaryOp.create_binop(20, 4, "/")

    def test_addition_with_binary_op(self):
        assert BinaryOp.create_binop(BinaryOp(Arg(0), 5, "+"), Arg(0), "+") == BinaryOp(
            BinaryOp(Arg(0), 5, "+"), Arg(0), "+"
        )


class TestBitwiseBinaryOp:
    def test_bitwise_operations_sanity(self):
        assert BinaryOp(Arg(0), Arg(1), "&") == BinaryOp.create_binop(Arg(0), Arg(1), "&")
        assert BinaryOp(Arg(0), Arg(1), "|") == BinaryOp.create_binop(Arg(0), Arg(1), "|")
        assert BinaryOp(Arg(0), Arg(1), "^") == BinaryOp.create_binop(Arg(0), Arg(1), "^")

    def test_associative_bitwise_operations(self):
        assert BinaryOp(Arg(0), 2, "&") == BinaryOp.create_binop(BinaryOp(Arg(0), 3, "&"), 2, "&")
        assert BinaryOp(Arg(0), 7, "|") == BinaryOp.create_binop(BinaryOp(Arg(0), 3, "|"), 4, "|")
