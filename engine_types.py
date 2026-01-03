from __future__ import annotations
from dataclasses import dataclass
from enum import IntEnum
from typing import Any, Mapping, TypeAlias
import operator

from binary_function import BinaryFunction, Loop
from project import Project

LoopsDict: TypeAlias = Mapping[int, list[Loop]]


def repr_or_hexint(val: Any) -> str:
    if isinstance(val, int):
        return hex(val)

    return repr(val)


@dataclass(frozen=True)
class Register:
    offset: int
    address: int
    project: Project

    def __repr__(self):
        return f"{{{self.project.arch_regs.names[self.offset]}@{hex(self.address)}}}"


@dataclass(frozen=True)
class Arg:
    index: int

    def __repr__(self):
        return f"arg{self.index}"


@dataclass(frozen=True)
class UnaryOp:
    obj: Any
    op: str

    def __repr__(self):
        return f"{self.op}{repr_or_hexint(self.obj)}"


@dataclass(frozen=True)
class BinaryOp:
    left: Any
    right: Any
    op: str
    signed: bool = False

    def __repr__(self):
        return f"({repr_or_hexint(self.left)} {self.op} {repr_or_hexint(self.right)})"

    @staticmethod
    def _eval_numeric_expression(left: int, right: int, op: str):
        return BinaryOp._INTEGER_OPS[op](left, right) & BinaryOp._BITNESS_TO_MASK[BinaryOp._PTR_SIZE]

    _BITNESS_TO_MASK = {
        32: 0xFFFFFFFF,
        64: 0xFFFFFFFFFFFFFFFF,
    }
    _PTR_SIZE = 32
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
    _COMPERISON_OPS = {"==", "!=", "<", "<=", ">", ">="}
    _MONOID = {"+": 0, "*": 1, "|": 0, "^": 0, "-": 0}

    @staticmethod
    def create_binop(left: Any, right: Any, op: str, signed: bool = False) -> BinaryOp | int:
        if isinstance(left, int) and isinstance(right, int):
            return BinaryOp._eval_numeric_expression(left, right, op)

        elif isinstance(left, BinaryOp) and isinstance(right, int):
            if left.op == op and op in BinaryOp._ASSOCIATIVE_OPS and isinstance(left.right, int):
                return BinaryOp(left.left, BinaryOp._eval_numeric_expression(left.right, right, op), op)
            elif left.op in BinaryOp._COMPERISON_OPS and right == 0:
                if op == "!=":
                    return left
                elif op == "==":
                    return left.negate()
            elif left.op == "^" and right == 1 and op == "<" and not signed:
                return BinaryOp(left.left, left.right, "==")

        elif right == BinaryOp._MONOID.get(op, None):
            return left
        elif left == BinaryOp._MONOID.get(op, None):
            return right

        return BinaryOp(left, right, op, signed)

    def negate(self) -> "BinaryOp":
        neg_op_map = {
            "==": "!=",
            "!=": "==",
            "<": ">=",
            "<=": ">",
            ">": "<=",
            ">=": "<",
        }
        if self.op not in neg_op_map:
            raise ValueError(f"Cannot negate binary operation with operator '{self.op}'")

        return BinaryOp(self.left, self.right, neg_op_map[self.op])


@dataclass(frozen=True)
class ConditionalSite:
    addr: int
    condition: BinaryOp
    iftrue: int
    iffalse: int

    def __repr__(self):
        return f"goto {repr_or_hexint(self.iftrue)} if {self.condition!r} else {hex(self.iffalse)}"


@dataclass(frozen=True)
class CallSite:
    addr: int
    target: int
    args: Mapping[int, Any]

    def __repr__(self):
        return f"({repr_or_hexint(self.target)})({', '.join(repr(self.args[arg_idx]) for arg_idx in sorted(self.args.keys()))})"


@dataclass(frozen=True)
class ConditionalExpression:
    condsite: ConditionalSite
    iftrue: Any
    iffalse: Any

    def __repr__(self):
        return f"({repr_or_hexint(self.iftrue)} if({self.condsite.condition!r} at {hex(self.condsite.addr)}) else {repr_or_hexint(self.iffalse)})"

    def collect_values(self) -> list[Any]:
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
    base: Any
    offset: Any
    access_type: MemoryAccessType
    stored_value: Any | None = None

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
            self.base == other.base
            and self.offset == other.offset
            and self.access_type == other.access_type
            and self.stored_value == other.stored_value
        )
