import abc

from typing import Any


class MemoryAccess(abc.ABC):
    """Read-only view of the loaded program image, addressed by virtual address."""

    @abc.abstractmethod
    def read(self, address: int, size: int) -> bytes: ...


class ELFMemoryAccess(MemoryAccess):
    def __init__(self, loader: Any):
        self._loader = loader

    def read(self, address: int, size: int) -> bytes:
        return self._loader.memory.load(address, size)
