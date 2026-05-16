"""Drop-in speedup for pyelftools symbol-table parsing.

cle's `__register_section_symbols` calls `SymbolTableSection.iter_symbols()`,
and stock pyelftools parses every Elf(32|64)_Sym one at a time through the
pure-Python `construct` parser (plus a per-name cstring stream parse). On a
binary with ~8.6k symbols that is the single dominant cost of loading.

The symbol table is a fixed-stride array of trivial fixed-width fields, so we
parse the whole thing with one `struct.Struct` and slice all names out of one
string-table read. The objects we hand back are the *same* types stock
pyelftools produces (`sections.Symbol` wrapping `construct` `Container`s, with
the identical enum-decoded fields), so cle and any other consumer keep working
unchanged. `install()` is idempotent.
"""

import struct

from elftools.elf import sections
from elftools.construct.lib import Container
from elftools.elf.enums import (
    ENUM_ST_INFO_BIND,
    ENUM_ST_INFO_TYPE,
    ENUM_ST_VISIBILITY,
    ENUM_ST_LOCAL,
    ENUM_ST_SHNDX,
)


def _invert(enum: dict) -> dict:
    # pyelftools Enum has `_default_: Pass`, so an unmapped value decodes to the
    # raw int. `.get(v, v)` reproduces exactly that.
    return {v: k for k, v in enum.items() if k != "_default_"}


_BIND = _invert(ENUM_ST_INFO_BIND)
_TYPE = _invert(ENUM_ST_INFO_TYPE)
_VIS = _invert(ENUM_ST_VISIBILITY)
_LOCAL = _invert(ENUM_ST_LOCAL)
_SHNDX = _invert(ENUM_ST_SHNDX)

# 32-bit Elf_Sym: name u32, value u32, size u32, info u8, other u8, shndx u16
# 64-bit Elf_Sym: name u32, info u8, other u8, shndx u16, value u64, size u64
_STRUCT = {
    (32, True): struct.Struct("<IIIBBH"),
    (32, False): struct.Struct(">IIIBBH"),
    (64, True): struct.Struct("<IBBHQQ"),
    (64, False): struct.Struct(">IBBHQQ"),
}


def _build_symbols(self):
    n = self.num_symbols()

    self.stream.seek(self["sh_offset"])
    raw = self.stream.read(self["sh_size"])
    entsize = self["sh_entsize"]

    strtab = self.stringtable
    strtab.stream.seek(strtab["sh_offset"])
    strblob = strtab.stream.read(strtab["sh_size"])

    sfmt = _STRUCT[(self.elffile.elfclass, self.elffile.little_endian)]
    is32 = self.elffile.elfclass == 32

    symbols = []
    for i in range(n):
        fields = sfmt.unpack_from(raw, i * entsize)
        if is32:
            st_name, st_value, st_size, st_info, st_other, st_shndx = fields
        else:
            st_name, st_info, st_other, st_shndx, st_value, st_size = fields

        if st_name:
            end = strblob.find(b"\x00", st_name)
            name = strblob[st_name : len(strblob) if end == -1 else end].decode("utf-8", errors="replace")
        else:
            name = ""

        entry = Container(
            st_name=st_name,
            st_value=st_value,
            st_size=st_size,
            st_info=Container(
                bind=_BIND.get(st_info >> 4, st_info >> 4),
                type=_TYPE.get(st_info & 0xF, st_info & 0xF),
            ),
            st_other=Container(
                local=_LOCAL.get((st_other >> 5) & 0x7, (st_other >> 5) & 0x7),
                visibility=_VIS.get(st_other & 0x7, st_other & 0x7),
            ),
            st_shndx=_SHNDX.get(st_shndx, st_shndx),
        )
        symbols.append(sections.Symbol(entry, name))

    return symbols


def _cached(self):
    cache = self.__dict__.get("_fast_symbols")
    if cache is None:
        cache = _build_symbols(self)
        self._fast_symbols = cache
    return cache


def _get_symbol(self, n):
    return _cached(self)[n]


def _iter_symbols(self):
    return iter(_cached(self))


def install() -> None:
    if getattr(sections.SymbolTableSection, "_fast_elf_installed", False):
        return
    sections.SymbolTableSection.get_symbol = _get_symbol
    sections.SymbolTableSection.iter_symbols = _iter_symbols
    sections.SymbolTableSection._fast_elf_installed = True


install()
