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

    def test_xor_compared_with_zero_simplifies(self):
        # (a ^ b) == 0 → a == b (XOR is zero exactly when operands are equal).
        # Same structural rule as the subtraction case.
        assert BinaryOp(Arg(0), Arg(1), "==") == BinaryOp.create_binop(
            BinaryOp(Arg(0), Arg(1), "^"), 0, "=="
        )
        assert BinaryOp(Arg(0), Arg(1), "!=") == BinaryOp.create_binop(
            BinaryOp(Arg(0), Arg(1), "^"), 0, "!="
        )

    def test_less_than_one_unsigned_is_equal_zero(self):
        # x <u 1 ≡ x == 0 for any unsigned 32-bit value.
        assert BinaryOp(Arg(0), 0, "==") == BinaryOp.create_binop(Arg(0), 1, "<", signed=False)
        # Composes with the (a ^ b) == 0 → a == b rule:
        #   (a ^ b) <u 1 → (a ^ b) == 0 → a == b
        assert BinaryOp(Arg(0), Arg(1), "==") == BinaryOp.create_binop(
            BinaryOp(Arg(0), Arg(1), "^"), 1, "<", signed=False
        )

    def test_add_constant_compared_with_zero(self):
        # (a + c) == 0 ⟺ a == -c (mod 2^32) — pull the constant across the comparison.
        # ARM CMN feeds INT_EQUAL with this exact shape and we want a clean equality.
        assert BinaryOp(Arg(0), 0xFFFFF000, "==") == BinaryOp.create_binop(
            BinaryOp(Arg(0), 0x1000, "+"), 0, "=="
        )
        assert BinaryOp(Arg(0), 0xFFFFFFFB, "!=") == BinaryOp.create_binop(
            BinaryOp(Arg(0), 5, "+"), 0, "!="
        )


class TestCombineComparisons:
    def test_and_collapses_redundant_pair(self):
        # (a >= c) & (a != c) → a > c, and the symmetric (a <= c) & (a != c) → a < c.
        # This is the shape ARM produces after CMN-then-BHI once INT_CARRY is lifted.
        assert BinaryOp(Arg(0), 5, ">") == BinaryOp.create_binop(
            BinaryOp(Arg(0), 5, ">="), BinaryOp(Arg(0), 5, "!="), "&"
        )
        assert BinaryOp(Arg(0), 5, "<") == BinaryOp.create_binop(
            BinaryOp(Arg(0), 5, "<="), BinaryOp(Arg(0), 5, "!="), "&"
        )

    def test_or_union_of_disjoint_pieces(self):
        # (a < c) | (a == c) → a <= c — the union of the strict-less and equality sets.
        # Shows up on ARM's MOVLS skip condition (!CY | ZR).
        assert BinaryOp(Arg(0), 5, "<=") == BinaryOp.create_binop(
            BinaryOp(Arg(0), 5, "<"), BinaryOp(Arg(0), 5, "=="), "|"
        )
        assert BinaryOp(Arg(0), 5, ">=") == BinaryOp.create_binop(
            BinaryOp(Arg(0), 5, ">"), BinaryOp(Arg(0), 5, "=="), "|"
        )

    def test_empty_intersection_collapses_to_zero(self):
        # (a > c) & (a < c) is impossible — the engine should collapse to 0.
        assert 0 == BinaryOp.create_binop(
            BinaryOp(Arg(0), 5, ">"), BinaryOp(Arg(0), 5, "<"), "&"
        )

    def test_full_union_collapses_to_one(self):
        # (a == c) | (a != c) covers everything → 1.
        assert 1 == BinaryOp.create_binop(
            BinaryOp(Arg(0), 5, "=="), BinaryOp(Arg(0), 5, "!="), "|"
        )

    def test_does_not_combine_when_operands_differ(self):
        # Only same-operand comparisons combine — different left or right operands stay.
        lhs = BinaryOp(Arg(0), 5, ">=")
        rhs = BinaryOp(Arg(0), 6, "!=")  # different right operand
        assert BinaryOp(lhs, rhs, "&") == BinaryOp.create_binop(lhs, rhs, "&")

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
