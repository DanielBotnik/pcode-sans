from functools import lru_cache
from typing import Mapping
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
    does_isa_switches: bool
    names: Mapping[int, str]


class Project:

    def __init__(self, language: str | pypcode.ArchLanguage):
        self.context = pypcode.Context(language)
        self.arch_regs = Project._create_arch_registers(self.context)

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

        for label in cspec.iterfind("default_proto/prototype/input/pentry/addr"):
            if label.get("space") != "stack":
                continue

            reg_offset = label.get("offset")
            if reg_offset is None:
                continue

            stack_argument_offset = int(reg_offset)

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
            does_isa_switches=("ISAModeSwitch" in context.registers),
            rev_arguments={v: k for k, v in args.items()},
            names={reg.offset: name for name, reg in context.registers.items()},
        )
