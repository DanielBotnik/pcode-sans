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

    def test_associative_arithemtic_operations(self):
        assert BinaryOp(Arg(0), 5, "+") == BinaryOp.create_binop(BinaryOp(Arg(0), 2, "+"), 3, "+")
        assert BinaryOp(Arg(0), 6, "*") == BinaryOp.create_binop(BinaryOp(Arg(0), 2, "*"), 3, "*")

    def test_arithmetic_operations_of_integers(self):
        assert 9 == BinaryOp.create_binop(5, 4, "+")
        assert 1 == BinaryOp.create_binop(5, 4, "-")
        assert 20 == BinaryOp.create_binop(5, 4, "*")
        assert 5 == BinaryOp.create_binop(20, 4, "/")


class TestBitwiseBinaryOp:
    def test_bitwise_operations_sanity(self):
        assert BinaryOp(Arg(0), Arg(1), "&") == BinaryOp.create_binop(Arg(0), Arg(1), "&")
        assert BinaryOp(Arg(0), Arg(1), "|") == BinaryOp.create_binop(Arg(0), Arg(1), "|")
        assert BinaryOp(Arg(0), Arg(1), "^") == BinaryOp.create_binop(Arg(0), Arg(1), "^")

    def test_associative_bitwise_operations(self):
        assert BinaryOp(Arg(0), 2, "&") == BinaryOp.create_binop(BinaryOp(Arg(0), 3, "&"), 2, "&")
        assert BinaryOp(Arg(0), 7, "|") == BinaryOp.create_binop(BinaryOp(Arg(0), 3, "|"), 4, "|")
