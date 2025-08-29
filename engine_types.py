from dataclasses import dataclass
from enum import IntEnum
from typing import Any, Mapping

from binary_function import BinaryFunction


def repr_or_hexint(val: Any) -> str:
    if isinstance(val, int):
        return hex(val)

    return repr(val)


class RegisterBase:
    pass


@dataclass(frozen=True)
class Register(RegisterBase):
    offset: int
    address: int
    bin_func: BinaryFunction

    def __repr__(self):
        return f"{{{self.bin_func.project.get_register_name(self.offset)}@{hex(self.address)}}}"


@dataclass(frozen=True)
class Arg(RegisterBase):
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

    def __repr__(self):
        return f"({repr_or_hexint(self.left)} {self.op} {repr_or_hexint(self.right)})"


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
