from typing import Mapping
import weakref
import pypcode

from dataclasses import dataclass


@dataclass
class ArchRegisters:
    stackpointer: int
    ret: int
    arguments: Mapping[int, int]
    unaffected: set[int]
    rev_arguments: Mapping[int, int]
    stack_argument_offset: int
    pointer_size: int
    does_isa_switches: bool
    names: Mapping[int, str]


class Project:
    # At most one Project may exist at a time. Constructing one registers it as
    # THE current project, so the rest of the engine can reach arch info
    # (register names, word size) without threading a `project` argument through
    # every constructor. To switch architectures you must drop all references to
    # the live project first — its __del__ clears the slot. The slot is a
    # weakref so it doesn't keep the project alive by itself (otherwise __del__
    # could never run and a second Project could never be created).
    _current: "weakref.ref[Project] | None" = None

    _cached_context_defaults: Mapping[str | pypcode.ArchLanguage, pypcode.Context] = dict()

    def __init__(self, language: str | pypcode.ArchLanguage):
        if Project._live() is not None:
            raise RuntimeError(
                "A Project already exists; release it (it must be __del__'d) before constructing another"
            )

        if language in Project._cached_context_defaults:
            context = Project._cached_context_defaults[language]
        else:
            context = pypcode.Context(language)
            Project._cached_context_defaults[language] = context

        self.context = context
        self.arch_regs = Project._create_arch_registers(self.context)
        Project._current = weakref.ref(self)

    def __del__(self):
        # Free the slot once this project is collected so a new one can be made.
        if Project._current is not None and Project._current() is self:
            Project._current = None

    @classmethod
    def _live(cls) -> "Project | None":
        return cls._current() if cls._current is not None else None

    @classmethod
    def current(cls) -> "Project":
        proj = cls._live()
        if proj is None:
            raise RuntimeError("No Project has been constructed yet")
        return proj

    @property
    def word_bits(self) -> int:
        return self.arch_regs.pointer_size * 8

    @property
    def word_mask(self) -> int:
        return (1 << self.word_bits) - 1

    def to_signed(self, value: int) -> int:
        bits = self.word_bits
        value &= (1 << bits) - 1
        return value - (1 << bits) if value & (1 << (bits - 1)) else value

    def to_unsigned(self, value: int) -> int:
        return value & self.word_mask

    @staticmethod
    def _create_arch_registers(context: pypcode.Context) -> ArchRegisters:
        language = context.language

        def find_matching_cid(language, desired):
            for cid in language.cspecs:
                if cid[0] == desired:
                    return cid
            return None

        cspec_id = (
            find_matching_cid(language, "default") or find_matching_cid(language, "gcc") or list(language.cspecs)[0]
        )
        cspec = language.cspecs[cspec_id]

        stackpointer_label = cspec.find("stackpointer")
        if stackpointer_label is None:
            raise ValueError("Could not find stackpointer label in cspec")
        sp_tag = stackpointer_label.get("register")
        if sp_tag is None:
            raise ValueError("Could not find stackpointer register in cspec")
        sp_off = context.registers[sp_tag].offset
        pointer_size = context.registers[sp_tag].size

        ret_off = None
        for label in cspec.iterfind("prototype/output/pentry[register]"):
            if label.get("metatype") is not None:
                continue

            reg_label = label.find("register")
            if reg_label is None:
                continue

            reg_name = reg_label.get("name")
            if reg_name is None:
                continue

            ret_off = context.registers[reg_name].offset

        if ret_off is None:
            raise ValueError("Could not find return register in cspec")

        args: dict[int, int] = dict()
        for label in cspec.iterfind("default_proto/prototype/input/pentry[register]"):
            if label.get("metatype") is not None:
                continue

            reg_label = label.find("register")
            if reg_label is None:
                continue

            reg_name = reg_label.get("name")
            if reg_name is None:
                continue

            args[len(args)] = context.registers[reg_name].offset

        stack_argument_offset = None
        for label in cspec.iterfind("default_proto/prototype/input/pentry/addr"):
            if label.get("space") != "stack":
                continue

            reg_offset = label.get("offset")
            if reg_offset is None:
                continue

            stack_argument_offset = int(reg_offset)

        if stack_argument_offset is None:
            raise ValueError("Could not find stack argument offset in cspec")

        unaffected = set()
        for label in cspec.iterfind("default_proto/prototype/unaffected/register"):
            reg_name = label.get("name")
            if reg_name is None:
                continue
            unaffected.add(context.registers[reg_name].offset)

        return ArchRegisters(
            stackpointer=sp_off,
            ret=ret_off,
            arguments=args,
            unaffected=unaffected,
            stack_argument_offset=stack_argument_offset,
            pointer_size=pointer_size,
            does_isa_switches=("ISAModeSwitch" in context.registers),
            rev_arguments={v: k for k, v in args.items()},
            names={reg.offset: name for name, reg in context.registers.items()},
        )
