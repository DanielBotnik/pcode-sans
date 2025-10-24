from __future__ import annotations
from dataclasses import dataclass
import pypcode

from engine_types import (
    Arg,
    BinaryOp,
    CallSite,
    ConditionalExpression,
    ConditionalSite,
    Register,
    MemoryAccess,
    MemoryAccessType,
    UnaryOp,
)
from typing import Any, Callable, Optional
from frozendict import frozendict
from binary_function import BinaryFunction, FunctionBlock
import operator

BITNESS_TO_MASK = {
    32: 0xFFFFFFFF,
    64: 0xFFFFFFFFFFFFFFFF,
}

PTR_SIZE = 32


def eval_numeric_expression(left: int, right: int, op: str, res_size: int):
    return OPS[op](left, right) & BITNESS_TO_MASK[res_size]


OPS = {
    "+": operator.add,
    "-": operator.sub,
    "x": operator.mul,  # 'x' is mul so it doesn't get confusing with '*'
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


class InstructionState:
    def __init__(self):
        self.regs: dict[int, Any] = {}
        self.unique: dict[int, Any] = {}
        self.ram: dict[int, Any] = {}
        self.stack: dict[int, Any] = {}
        self.last_callsite: Optional[CallSite] = None
        self.goto_state: dict[int, InstructionState] = dict()

    def copy(self) -> InstructionState:
        new_state = InstructionState()
        new_state.regs = self.regs.copy()
        new_state.unique = self.unique.copy()
        new_state.ram = self.ram.copy()
        new_state.stack = self.stack.copy()
        new_state.last_callsite = self.last_callsite
        return new_state


class Engine:

    def __init__(self, bin_func: BinaryFunction):
        self.bin_func = bin_func
        self.instructions_state: dict[int, InstructionState] = dict()
        self.current_inst: int = 0
        self.previous_marks: list[int] = list()
        self._handlers: dict[pypcode.OpCode, Callable[[Engine, pypcode.PcodeOp], None]] = {}
        self.callsites: list[CallSite] = []
        self.conditional_sites: list[ConditionalSite] = []
        self.memory_accesses: list[MemoryAccess] = []
        self.addr_to_conditional_site: dict[int, ConditionalSite] = {}
        self.current_blk: FunctionBlock = None
        self.__unfinished_condsite: Optional[_UnfinishedConditionalSite] = None

        self._init_handlers()

        for current_addr in self.bin_func.code_flow_grpah.traverse():
            blk = self.bin_func.blocks_dict_start_address[current_addr]
            parents = self.bin_func.code_flow_grpah.get_parnets(current_addr)
            self.previous_marks = [self.bin_func.blocks_dict[parent].last_instruction_addr for parent in parents]
            self._analyze_block(blk)

    def _init_handlers(self):
        self._handlers.update(
            {
                pypcode.OpCode.IMARK: self._handle_imark,
                pypcode.OpCode.INT_ADD: self._handle_int_add,
                pypcode.OpCode.INT_LEFT: self._handle_int_left,
                pypcode.OpCode.INT_LESS: self._handle_int_less,
                pypcode.OpCode.INT_EQUAL: self._handle_int_equal,
                pypcode.OpCode.COPY: self._handle_copy,
                pypcode.OpCode.STORE: self._handle_store,
                pypcode.OpCode.INT_AND: self._handle_int_and,
                pypcode.OpCode.INT_NOTEQUAL: self._handle_int_notequal,
                pypcode.OpCode.INT_2COMP: self._handle_int_2comp,
                pypcode.OpCode.CALLIND: self._handle_callind,
                pypcode.OpCode.CALL: self._handle_call,
                pypcode.OpCode.CALLOTHER: self._do_nothing,  # TODO: Think if required, example is MIPS `rdhwr` in `sshd` `fileno` Function
                pypcode.OpCode.INT_ZEXT: self._handle_int_zext,
                pypcode.OpCode.LOAD: self._handle_load,
                pypcode.OpCode.CBRANCH: self._handle_cbranch,
                pypcode.OpCode.BRANCH: self._handle_branch,
                pypcode.OpCode.BRANCHIND: self._handle_branchind,
                pypcode.OpCode.RETURN: self._do_nothing,
                pypcode.OpCode.INT_SLESS: self._handle_int_sless,
                pypcode.OpCode.INT_SLESSEQUAL: self._handle_int_slessequal,
                pypcode.OpCode.BOOL_NEGATE: self._handle_bool_negate,
                pypcode.OpCode.INT_RIGHT: self._handle_int_right,
            }
        )

    def _analyze_block(self, blk: FunctionBlock):
        self.current_blk = blk
        current_address = blk.start

        while current_address < blk.end:
            for op in self.bin_func.opcodes[current_address].ops:
                handler = self._handlers.get(op.opcode, None)
                if handler is not None:
                    handler(op)
                else:
                    print(op.opcode)
            current_address += self.bin_func.opcodes[current_address].bytes_size

    def __clear_after_callsite(self, instruction_state: InstructionState) -> None:
        if instruction_state.last_callsite is None:
            return

        for reg in list(instruction_state.regs.keys()):
            if reg not in self.bin_func.project.get_unaffected_registers():
                del instruction_state.regs[reg]

        instruction_state.regs[self.bin_func.project.get_ret_register()] = instruction_state.last_callsite
        instruction_state.last_callsite = None

    def __merge_dicts(self, x_dict, y_dict, condsite, iftrue, iffalse):
        """Merge two dict-like states using ConditionalExpression when values differ."""
        merged = {}
        for k in x_dict.keys() & y_dict.keys():
            xv, yv = x_dict[k], y_dict[k]
            merged[k] = xv if xv == yv else ConditionalExpression(condsite, iftrue[k], iffalse[k])
        return merged

    def _handle_imark(self, op: pypcode.PcodeOp):
        self.current_inst = op.inputs[0].offset
        self.__unfinished_condsite = None

        if self.current_inst in self.bin_func.loops_dict_start_address:
            good_marks = []
            for mark in self.previous_marks:
                if self.bin_func.blocks_dict[mark].start not in self.bin_func.loops_dict[self.current_inst].blocks:
                    good_marks.append(mark)
            self.previous_marks = good_marks

        if len(self.previous_marks) == 0:
            self.instructions_state[self.current_inst] = InstructionState()
            self.previous_marks = [self.current_inst]
            return

        if len(self.previous_marks) == 1:
            if self.current_inst in self.instructions_state[self.previous_marks[0]].goto_state:
                self.instructions_state[self.current_inst] = (
                    self.instructions_state[self.previous_marks[0]].goto_state[self.current_inst].copy()
                )
            else:
                self.instructions_state[self.current_inst] = self.instructions_state[self.previous_marks[0]].copy()
            self.__clear_after_callsite(self.instructions_state[self.current_inst])

        elif len(self.previous_marks) == 2:
            try:
                blk_a = self.bin_func.blocks_dict[self.previous_marks[0]]
                blk_b = self.bin_func.blocks_dict[self.previous_marks[1]]

                x = self.instructions_state[self.previous_marks[0]]
                if self.current_inst in x.goto_state:
                    x = x.goto_state[self.current_inst]
                y = self.instructions_state[self.previous_marks[1]]
                if self.current_inst in y.goto_state:
                    y = y.goto_state[self.current_inst]
                self.__clear_after_callsite(x)
                self.__clear_after_callsite(y)

                common_ancestor_addr = self.bin_func.common_ancestor(blk_a.start, blk_b.start)
                common_condsite = self.addr_to_conditional_site[common_ancestor_addr]

                iftrue_state, iffalse_state = None, None

                if self.bin_func.is_ancestor(blk_a.start, common_condsite.iffalse):
                    iftrue_state, iffalse_state = x, y
                else:
                    iftrue_state, iffalse_state = y, x

                common_instruction_state = InstructionState()
                common_instruction_state.regs = self.__merge_dicts(
                    x.regs, y.regs, common_condsite, iftrue_state.regs, iffalse_state.regs
                )
                common_instruction_state.unique = self.__merge_dicts(
                    x.unique, y.unique, common_condsite, iftrue_state.unique, iffalse_state.unique
                )
                common_instruction_state.ram = self.__merge_dicts(
                    x.ram, y.ram, common_condsite, iftrue_state.ram, iffalse_state.ram
                )
                common_instruction_state.stack = self.__merge_dicts(
                    x.stack, y.stack, common_condsite, iftrue_state.stack, iffalse_state.stack
                )

                self.instructions_state[self.current_inst] = common_instruction_state
            except Exception as nig:
                print(nig)
                import ipdb

                ipdb.set_trace()
                print("a")

        else:
            # TODO: care about diffrences
            common_instruction_state = InstructionState()

            previous_instruction_states = [self.instructions_state[addr] for addr in self.previous_marks]
            for reg in set.intersection(*(set(s.regs.keys()) for s in previous_instruction_states)):
                common_instruction_state.regs[reg] = previous_instruction_states[0].regs[reg]
            for unique in set.intersection(*(set(s.unique.keys()) for s in previous_instruction_states)):
                common_instruction_state.unique[unique] = previous_instruction_states[0].unique[unique]
            for addr in set.intersection(*(set(s.ram.keys()) for s in previous_instruction_states)):
                common_instruction_state.ram[addr] = previous_instruction_states[0].ram[addr]
            for addr in set.intersection(*(set(s.stack.keys()) for s in previous_instruction_states)):
                common_instruction_state.stack[addr] = previous_instruction_states[0].stack[addr]

            self.instructions_state[self.current_inst] = common_instruction_state

        if self.current_inst in self.bin_func.loops_dict_start_address:
            for blk in self.bin_func.loops_dict[self.current_inst].blocks:
                for op in self.bin_func.opcodes[blk].ops:
                    if op.output is None:
                        continue

                    space = op.output.space.name
                    if space != "register":
                        continue

                    self.instructions_state[self.current_inst].regs.pop(op.output.offset, None)

        self.previous_marks = [self.current_inst]

    @staticmethod
    def _handle_binop(left, right, op: str):

        if isinstance(left, int) and isinstance(right, int):
            return eval_numeric_expression(left, right, op, PTR_SIZE)

        elif isinstance(left, BinaryOp):
            if left.op == op and op in ["+", "*", "&", "|"] and isinstance(left.right, int):
                return BinaryOp(left.left, eval_numeric_expression(left.right, right, op, PTR_SIZE), op)
            elif op in ["!=", "=="] and left.op in ["<", "<="] and right == 0:
                return BinaryOp(left.left, left.right, left.op)

        elif isinstance(right, int) and right == 0 and op == "+":
            return left

        return BinaryOp(left, right, op)

    def _handle_int_add(self, op: pypcode.PcodeOp):
        left = self.handle_get(op.inputs[0])
        right = self.handle_get(op.inputs[1])

        self.handle_put(op.output, self._handle_binop(left, right, "+"))

    def _handle_int_left(self, op: pypcode.PcodeOp):
        left = self.handle_get(op.inputs[0])
        right = self.handle_get(op.inputs[1])

        self.handle_put(op.output, self._handle_binop(left, right, "<<"))

    def _handle_int_less(self, op: pypcode.PcodeOp):
        left = self.handle_get(op.inputs[0])
        right = self.handle_get(op.inputs[1])

        self.handle_put(op.output, self._handle_binop(left, right, "<"))

    def _handle_int_equal(self, op: pypcode.PcodeOp):
        left = self.handle_get(op.inputs[0])
        right = self.handle_get(op.inputs[1])

        self.handle_put(op.output, self._handle_binop(left, right, "=="))

    def _handle_copy(self, op: pypcode.PcodeOp):
        self.handle_put(op.output, self.handle_get(op.inputs[0]))

    def _handle_store(self, op: pypcode.PcodeOp):
        space = op.inputs[0].getSpaceFromConst().name
        offset = self.handle_get(op.inputs[1])
        val = self.handle_get(op.inputs[2])

        if space == "ram":
            if isinstance(offset, int):
                self.instructions_state[self.current_inst].ram[offset] = val
            elif isinstance(offset, BinaryOp):
                right = offset.right
                left = offset.left
                if isinstance(right, int) and isinstance(left, Register) and offset.op == "+":
                    if left.offset != 116:  # sp offset, also add address check
                        raise RuntimeError("Supports only ram sp movements")

                import ctypes  # todo: support 64 bit

                signed_offset = ctypes.c_int32(right).value
                self.instructions_state[self.current_inst].stack[signed_offset] = val

        else:
            print("nigga", space)

    def _handle_int_and(self, op: pypcode.PcodeOp):
        left = self.handle_get(op.inputs[0])
        right = self.handle_get(op.inputs[1])

        self.handle_put(op.output, self._handle_binop(left, right, "&"))

    def _handle_int_notequal(self, op: pypcode.PcodeOp):
        left = self.handle_get(op.inputs[0])
        right = self.handle_get(op.inputs[1])

        self.handle_put(op.output, self._handle_binop(left, right, "!="))

    def _handle_int_2comp(self, op: pypcode.PcodeOp):
        val = op.inputs[0].offset  # INT_2COMP is always int values.

        self.handle_put(op.output, -val)

    def _handle_call(self, op: pypcode.PcodeOp):
        self._handle_callind(op)

    def _handle_callind(self, op: pypcode.PcodeOp):
        target = self.handle_get(op.inputs[0])

        # TODO: do this better
        if self.bin_func.project.context.language.id.startswith("MIPS:") and isinstance(target, BinaryOp):
            if target.left == -0x2 and target.op == "&":
                target = target.right

        args = frozendict(
            {
                arg_num: self.instructions_state[self.current_inst].regs[reg]
                for arg_num, reg in self.bin_func.project.get_args_registers().items()
                if reg in self.instructions_state[self.current_inst].regs
            }
        )

        callsite = CallSite(self.current_inst, target, args)

        self.callsites.append(callsite)
        self.instructions_state[self.current_inst].last_callsite = callsite

    def _handle_int_zext(self, op: pypcode.PcodeOp):
        # Assuming zext(X) == X for now.
        self.handle_put(op.output, self.handle_get(op.inputs[0]))

    def _create_condsite(self, condition: BinaryOp, goto_iftrue: int, goto_iffalse: int) -> None:
        condsite = ConditionalSite(self.current_inst, condition, goto_iftrue, goto_iffalse)
        self.conditional_sites.append(condsite)
        self.addr_to_conditional_site[self.current_blk.start] = condsite

        loop = self.bin_func.loops_dict.get(self.current_inst, None)
        if loop is not None and isinstance(condition, BinaryOp):
            if goto_iftrue not in loop.blocks:
                loop.exit_conditions[self.current_inst] = condition
            elif goto_iffalse not in loop.blocks:
                loop.exit_conditions[self.current_inst] = condition.negate()

    def _handle_branch(self, op: pypcode.PcodeOp):
        goto_addr = self.handle_get(op.inputs[0])

        if self.__unfinished_condsite is None:
            return

        self._create_condsite(self.__unfinished_condsite.condition, self.__unfinished_condsite.goto_iftrue, goto_addr)

    def _handle_cbranch(self, op: pypcode.PcodeOp):
        goto_iftrue = self.handle_get(op.inputs[0])
        goto_iffalse = self.bin_func._next_address(self.current_inst)
        condition: BinaryOp | int = self.handle_get(op.inputs[1])  # TODO: handle int conditions

        if goto_iffalse == goto_iftrue:
            self.instructions_state[self.current_inst].goto_state[goto_iftrue] = self.instructions_state[
                self.current_inst
            ].copy()
            self.__unfinished_condsite = _UnfinishedConditionalSite(condition, goto_iftrue)
            return

        self._create_condsite(condition, goto_iftrue, goto_iffalse)

    def _handle_int_sless(self, op: pypcode.PcodeOp):
        left = self.handle_get(op.inputs[0])
        right = self.handle_get(op.inputs[1])

        self.handle_put(op.output, self._handle_binop(left, right, "<"))

    def _handle_int_slessequal(self, op: pypcode.PcodeOp):
        left = self.handle_get(op.inputs[0])
        right = self.handle_get(op.inputs[1])

        self.handle_put(op.output, self._handle_binop(left, right, "<="))

    def _do_nothing(self, op: pypcode.PcodeOp):
        pass

    def _handle_branchind(self, op: pypcode.PcodeOp):
        target = self.handle_get(op.inputs[0])

        args = frozendict(
            {
                arg_num: self.instructions_state[self.current_inst].regs[reg]
                for arg_num, reg in self.bin_func.project.get_args_registers().items()
                if reg in self.instructions_state[self.current_inst].regs
            }
        )

        callsite = CallSite(self.current_inst, target, args)
        self.callsites.append(callsite)

    def _handle_bool_negate(self, op: pypcode.PcodeOp):
        bool_expr: BinaryOp = self.handle_get(op.inputs[0])

        self.handle_put(op.output, bool_expr.negate())

    def _handle_int_right(self, op: pypcode.PcodeOp):
        left = self.handle_get(op.inputs[0])
        right = self.handle_get(op.inputs[1])

        self.handle_put(op.output, self._handle_binop(left, right, ">>"))

    def _handle_load(self, op: pypcode.PcodeOp):
        space = op.inputs[0].getSpaceFromConst().name
        offset = self.handle_get(op.inputs[1])

        if space == "ram":

            require_deref = True

            if isinstance(offset, BinaryOp):
                if isinstance(offset.left, Register) and offset.left.offset == 116:
                    # todo: Add struct member access
                    import ctypes  #  todo: support 64 bit

                    signed_value = ctypes.c_int32(offset.right).value
                    res = self.instructions_state[self.current_inst].stack.get(signed_value, None)

                    # todo remove
                    if signed_value >= 0x10:
                        require_deref = False

                    if res is not None:
                        require_deref = False

            if require_deref:
                if isinstance(offset, (int, UnaryOp)):
                    res = UnaryOp(offset, "*")
                elif isinstance(offset, BinaryOp):
                    if isinstance(offset.left, Register) and offset.left.offset == 116:
                        pass  # TODO: Handle stack later
                    else:
                        res = MemoryAccess(self.current_inst, offset.left, offset.right, MemoryAccessType.LOAD)
                else:
                    res = MemoryAccess(self.current_inst, offset, 0, MemoryAccessType.LOAD)

                if isinstance(res, MemoryAccess):
                    self.memory_accesses.append(res)

        self.handle_put(op.output, res)

    def handle_get(self, input: pypcode.Varnode) -> Any:
        space = input.space.name

        if space == "register":
            reg = self.instructions_state[self.current_inst].regs.get(input.offset, None)
            if reg is not None:
                return reg

            if (
                input.offset in self.bin_func.project.get_rev_args_registers()
                and self.instructions_state[self.current_inst].last_callsite is None
            ):
                res = Arg(self.bin_func.project.get_rev_args_registers()[input.offset])
            else:
                res = Register(input.offset, self.current_inst, self.bin_func)
            self.instructions_state[self.current_inst].regs[input.offset] = res
            return res

        elif space == "const":
            return input.offset

        elif space == "unique":
            res = self.instructions_state[self.current_inst].unique.get(input.offset)
            if res is not None:
                return res

        elif space == "ram":
            res = self.instructions_state[self.current_inst].ram.get(input.offset)
            if res is not None:
                print("nigga not None")
            return input.offset

    def handle_put(self, output: pypcode.Varnode, val: Any):
        space = output.space.name

        if space == "register":
            self.instructions_state[self.current_inst].regs[output.offset] = val
        elif space == "unique":
            self.instructions_state[self.current_inst].unique[output.offset] = val
        else:
            raise RuntimeError(f"Unexpected space in handle_put: {space}")


@dataclass
class _UnfinishedConditionalSite:
    condition: BinaryOp
    goto_iftrue: int
