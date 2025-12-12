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

        sp_tag = cspec.find("stackpointer").attrib.get("register")
        sp_off = context.registers[sp_tag].offset

        for label in cspec.iterfind("prototype/output/pentry[register]"):
            if label.get("metatype") is not None:
                continue

            ret_off = context.registers[label.find("register").get("name")].offset

        args = dict()
        for label in cspec.iterfind("default_proto/prototype/input/pentry[register]"):
            if label.get("metatype") is not None:
                continue

            args[len(args)] = context.registers[label.find("register").get("name")].offset

        unaffected = set()
        for label in cspec.iterfind("default_proto/prototype/unaffected/register"):
            unaffected.add(context.registers[label.get("name")].offset)

        return ArchRegisters(
            stackpointer=sp_off,
            ret=ret_off,
            arguments=args,
            unaffected=unaffected,
            does_isa_switches=("ISAModeSwitch" in context.registers),
            rev_arguments={v: k for k, v in args.items()},
            names={reg.offset: name for name, reg in context.registers.items()},
        )
