from functools import lru_cache
import pypcode


class Project:

    def __init__(self, language: str | pypcode.ArchLanguage):
        self.context = pypcode.Context(language)

    @lru_cache
    def get_register_name(self, reg_offset: int) -> str:
        for reg_name, varnode in self.context.registers.items():
            if varnode.offset == reg_offset:
                return reg_name

        raise RuntimeError(f"Couldn't find reg with offset {reg_offset}")

    @lru_cache
    def get_ret_register(self) -> int:
        cspec = self.context.language.cspecs[("default", "default")]
        default_proto = cspec.find("default_proto")
        prototype = default_proto.find("prototype")

        output = prototype.find("output")

        for label in output.iterfind("pentry"):
            if label.get("metatype") is not None:
                continue

            reg = label.find("register")
            if reg is None:
                continue

            return self.context.registers[reg.get("name")].offset

    @lru_cache
    def get_args_registers(self) -> dict[int, int]:
        cspec = self.context.language.cspecs[("default", "default")]
        default_proto = cspec.find("default_proto")
        prototype = default_proto.find("prototype")
        args = dict()

        input_ = prototype.find("input")

        for label in input_.iterfind("pentry"):
            if label.get("metatype") is not None:
                continue

            reg = label.find("register")
            if reg is None:
                continue

            args[len(args)] = self.context.registers[reg.get("name")].offset

        return args

    @lru_cache
    def get_rev_args_registers(self) -> dict[int, int]:
        return {v: k for k, v in self.get_args_registers().items()}

    @lru_cache
    def get_unaffected_registers(self) -> set[int]:
        cspec = self.context.language.cspecs[("default", "default")]
        default_proto = cspec.find("default_proto")
        prototype = default_proto.find("prototype")
        regs = set()

        unaffected = prototype.find("unaffected")
        for label in unaffected.iterfind("register"):
            regs.add(self.context.registers[label.get("name")].offset)

        return regs
