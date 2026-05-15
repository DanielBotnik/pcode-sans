from __future__ import annotations
from dataclasses import dataclass, field
from enum import IntEnum
from typing import ClassVar, Mapping, TypeAlias
import operator

from project import Project



def repr_or_hexint(val: Value) -> str:
    if isinstance(val, int):
        return hex(val)

    return repr(val)


@dataclass(frozen=True)
class Register:
    offset: int
    address: int

    def __repr__(self):
        return f"{{{Project.current().arch_regs.names[self.offset]}@{hex(self.address)}}}"


@dataclass(frozen=True)
class Arg:
    index: int

    def __repr__(self):
        return f"arg{self.index}"


@dataclass(frozen=True)
class UnaryOp:
    obj: Value
    op: str

    def __repr__(self):
        return f"{self.op}{repr_or_hexint(self.obj)}"


@dataclass(frozen=True)
class BinaryOp:
    left: Value
    right: Value
    op: str
    signed: bool = False

    def __repr__(self):
        return f"({repr_or_hexint(self.left)} {self.op} {repr_or_hexint(self.right)})"

    @staticmethod
    def _eval_numeric_expression(left: int, right: int, op: str):
        return BinaryOp._INTEGER_OPS[op](left, right) & Project.current().word_mask

    _INTEGER_OPS = {
        "+": operator.add,
        "-": operator.sub,
        "*": operator.mul,
        "/": operator.floordiv,
        "%": operator.mod,
        "&": operator.and_,
        "|": operator.or_,
        "^": operator.xor,
        "<<": operator.lshift,
        ">>": operator.rshift,
        "==": lambda a, b: int(operator.eq(a, b)),
        "!=": lambda a, b: int(operator.ne(a, b)),
        "<": lambda a, b: int(operator.lt(a, b)),
        "<=": lambda a, b: int(operator.le(a, b)),
        ">": lambda a, b: int(operator.gt(a, b)),
        ">=": lambda a, b: int(operator.ge(a, b)),
    }
    _ASSOCIATIVE_OPS = {"+", "*", "&", "|", "^"}
    _COMPARISON_OPS = {"==", "!=", "<", "<=", ">", ">="}
    _MONOID = {"+": 0, "*": 1, "|": 0, "^": 0, "-": 0}

    # Each comparison `a OP c` is the set of integers (lt-of-c, eq-c, gt-of-c)
    # included. Combining two comparisons on the same (a, c) under & or | is
    # then bitwise AND / OR of these tuples, mapped back to an operator.
    _COMPARISON_SETS: ClassVar[dict[str, tuple[bool, bool, bool]]] = {
        "==": (False, True, False),
        "!=": (True, False, True),
        "<":  (True, False, False),
        "<=": (True, True, False),
        ">":  (False, False, True),
        ">=": (False, True, True),
    }
    _SETS_TO_COMPARISON: ClassVar[dict[tuple[bool, bool, bool], "str | int"]] = {
        **{v: k for k, v in _COMPARISON_SETS.items()},
        (False, False, False): 0,
        (True, True, True): 1,
    }

    @staticmethod
    def _combine_comparisons(op1: str, op2: str, combiner: str) -> "str | int":
        s1 = BinaryOp._COMPARISON_SETS[op1]
        s2 = BinaryOp._COMPARISON_SETS[op2]
        if combiner == "&":
            combined = (s1[0] and s2[0], s1[1] and s2[1], s1[2] and s2[2])
        else:  # "|"
            combined = (s1[0] or s2[0], s1[1] or s2[1], s1[2] or s2[2])
        return BinaryOp._SETS_TO_COMPARISON[combined]

    @staticmethod
    def create_binop(left: Value, right: Value, op: str, signed: bool = False) -> Value:
        if isinstance(left, int) and isinstance(right, int):
            return BinaryOp._eval_numeric_expression(left, right, op)
        if right == BinaryOp._MONOID.get(op):
            return left
        if op != "-" and left == BinaryOp._MONOID.get(op):
            return right
        # x <u 1 ≡ x == 0 — rewrite so the equality-zero rules below apply uniformly.
        if right == 1 and op == "<" and not signed:
            return BinaryOp.create_binop(left, 0, "==")
        # Combine two comparisons on the same (a, c) under & or |.
        if (
            op in {"&", "|"}
            and isinstance(left, BinaryOp)
            and isinstance(right, BinaryOp)
            and left.op in BinaryOp._COMPARISON_OPS
            and right.op in BinaryOp._COMPARISON_OPS
            and left.left == right.left
            and left.right == right.right
        ):
            combined = BinaryOp._combine_comparisons(left.op, right.op, op)
            return combined if isinstance(combined, int) else BinaryOp(left.left, left.right, combined)
        if not (isinstance(left, BinaryOp) and isinstance(right, int)):
            return BinaryOp(left, right, op, signed)

        # Treat - as + with the additive inverse: (x ± c1) ± c2 collapses to one + with a word-masked combined offset.
        if op in {"+", "-"} and left.op in {"+", "-"} and isinstance(left.right, int):
            c1 = left.right if left.op == "+" else -left.right
            c2 = right if op == "+" else -right
            combined = (c1 + c2) & Project.current().word_mask
            return left.left if combined == 0 else BinaryOp(left.left, combined, "+")
        if left.op == op and op in BinaryOp._ASSOCIATIVE_OPS and isinstance(left.right, int):
            return BinaryOp(left.left, BinaryOp._eval_numeric_expression(left.right, right, op), op)
        if left.op in BinaryOp._COMPARISON_OPS and right == 0 and op in {"==", "!="}:
            return left.negate() if op == "==" else left
        # Both - and ^ are zero exactly when their operands are equal — lift to comparison.
        if left.op in {"-", "^"} and right == 0 and op in {"==", "!="}:
            return BinaryOp(left.left, left.right, op)
        # (a + c) ==/!= 0 ⟺ a ==/!= -c (mod 2^word) — pull the constant across the comparison.
        if left.op == "+" and right == 0 and op in {"==", "!="} and isinstance(left.right, int):
            return BinaryOp(left.left, (-left.right) & Project.current().word_mask, op)

        return BinaryOp(left, right, op, signed)

    _NEG_OP_MAP = {
        "==": "!=", "!=": "==",
        "<": ">=", "<=": ">",
        ">": "<=", ">=": "<",
    }

    def negate(self) -> "BinaryOp":
        if self.op in BinaryOp._NEG_OP_MAP:
            return BinaryOp(self.left, self.right, BinaryOp._NEG_OP_MAP[self.op])
        if self.op == "&":
            # De Morgan: !(a & b) = !a | !b
            return BinaryOp(_negate_value(self.left), _negate_value(self.right), "|")
        if self.op == "|":
            # De Morgan: !(a | b) = !a & !b
            return BinaryOp(_negate_value(self.left), _negate_value(self.right), "&")
        raise ValueError(f"Cannot negate binary operation with operator '{self.op}'")


def _negate_value(v):
    """Logical negation of a boolean-typed Value (for use inside De Morgan)."""
    if isinstance(v, int):
        return 1 if v == 0 else 0
    if isinstance(v, BinaryOp):
        try:
            return v.negate()
        except ValueError:
            return UnaryOp(v, "!")
    if isinstance(v, UnaryOp) and v.op == "!":
        return v.obj  # !(!x) = x
    return UnaryOp(v, "!")


@dataclass(frozen=True)
class ConditionalSite:
    addr: int
    # Usually a comparison BinaryOp, but composite booleans (BOOL_AND/OR/!())
    # and merged-state ConditionalExpressions can also drive a branch.
    condition: "Value"
    iftrue: int
    iffalse: int

    def __repr__(self):
        return f"goto {repr_or_hexint(self.iftrue)} if {self.condition!r} else {hex(self.iffalse)}"


@dataclass(frozen=True)
class CallSite:
    addr: int
    target: Value
    args: Mapping[int, Value]

    def __repr__(self):
        return f"({repr_or_hexint(self.target)})({', '.join(repr(self.args[arg_idx]) for arg_idx in sorted(self.args.keys()))})"


@dataclass(frozen=True)
class ConditionalExpression:
    condsite: ConditionalSite
    iftrue: Value
    iffalse: Value

    def __repr__(self):
        return f"({repr_or_hexint(self.iftrue)} if({self.condsite.condition!r} at {hex(self.condsite.addr)}) else {repr_or_hexint(self.iffalse)})"

    def collect_values(self) -> list[Value]:
        values = []
        if isinstance(self.iftrue, ConditionalExpression):
            values.extend(self.iftrue.collect_values())
        else:
            values.append(self.iftrue)

        if isinstance(self.iffalse, ConditionalExpression):
            values.extend(self.iffalse.collect_values())
        else:
            values.append(self.iffalse)

        return values


class MemoryAccessType(IntEnum):
    LOAD = 0
    STORE = 1


@dataclass(frozen=True)
class MemoryAccess:
    addr: int
    base: Value
    offset: Value
    access_type: MemoryAccessType
    stored_value: Value | None = None

    def __repr__(self):
        addition_str = "" if self.offset == 0 else f" + {repr_or_hexint(self.offset)}"

        if self.access_type == MemoryAccessType.LOAD:
            return f"*({repr_or_hexint(self.base)}{addition_str})"
        else:
            return f"*({repr_or_hexint(self.base)}{addition_str}) = {repr_or_hexint(self.stored_value)}"

    def __eq__(self, other):
        if not isinstance(other, MemoryAccess):
            return False
        return (
            self.addr == other.addr
            and self.base == other.base
            and self.offset == other.offset
            and self.access_type == other.access_type
            and self.stored_value == other.stored_value
        )

    def __hash__(self):
        return hash((self.addr, self.base, self.offset, self.access_type, self.stored_value))


@dataclass
class Loop:
    start: int
    blocks: set[int] = field(default_factory=set)
    exit_conditions: dict[int, BinaryOp] = field(default_factory=dict)


LoopsDict: TypeAlias = Mapping[int, list[Loop]]

Value: TypeAlias = int | Register | Arg | BinaryOp | UnaryOp | CallSite | MemoryAccess | ConditionalExpression
