from typing import Any, Iterable, Iterator
from dataclasses import dataclass


@dataclass(frozen=True)
class Symbol:
    name: str
    address: int
    size: int
    is_function: bool


class SymbolTable:
    """Every symbol known to the project, indexed by name and by address.
    The first symbol seen for a given name/address wins the index lookup, but
    iteration yields all of them so callers can still see aliases/duplicates."""

    def __init__(self, symbols: Iterable[Symbol] = ()):
        self._symbols: list[Symbol] = []
        self._by_name: dict[str, Symbol] = {}
        self._by_address: dict[int, Symbol] = {}
        for symbol in symbols:
            self.add(symbol)

    def add(self, symbol: Symbol) -> None:
        self._symbols.append(symbol)
        self._by_name.setdefault(symbol.name, symbol)
        self._by_address.setdefault(symbol.address, symbol)

    def by_name(self, name: str) -> "Symbol | None":
        return self._by_name.get(name)

    def by_address(self, address: int) -> "Symbol | None":
        return self._by_address.get(address)

    def __iter__(self) -> Iterator[Symbol]:
        return iter(self._symbols)

    def __len__(self) -> int:
        return len(self._symbols)

    def __contains__(self, name: object) -> bool:
        return name in self._by_name

    @classmethod
    def from_loader(cls, loader: Any) -> "SymbolTable":
        return cls(
            Symbol(s.name, s.rebased_addr, s.size, s.is_function)
            for s in loader.main_object.symbols
            if s.name
        )
