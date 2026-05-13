from __future__ import annotations
from dataclasses import dataclass

import pypcode
import ctypes

from engine_types import (
    Arg,
    BinaryOp,
    CallSite,
    ConditionalExpression,
    ConditionalSite,
    LoopsDict,
    Register,
    MemoryAccess,
    MemoryAccessType,
    UnaryOp,
    Value,
)
from typing import Callable, ClassVar, Optional
from frozendict import frozendict
from binary_function import BinaryFunction, CBRANCH_SKIP_ADDR, FunctionBlock
from project import ArchRegisters


class InstructionState:
    def __init__(self):
        self.regs: dict[int, Value] = {}
        self.unique: dict[int, Value] = {}
        self.ram: dict[int, Value] = {}
        self.stack: dict[int, Value] = {}
        self.last_callsite: Optional[CallSite] = None
        self.goto_state: dict[int, InstructionState] = dict()
        self.used_arguments: set[int] = set()

    def copy(self) -> InstructionState:
        new_state = InstructionState()
        new_state.regs = self.regs.copy()
        new_state.unique = self.unique.copy()
        new_state.ram = self.ram.copy()
        new_state.stack = self.stack.copy()
        new_state.last_callsite = self.last_callsite
        new_state.used_arguments = self.used_arguments.copy()
        return new_state

    @staticmethod
    def _merge_dicts(
        condsite: ConditionalSite, iftrue: dict[int, Value], iffalse: dict[int, Value]
    ) -> dict[int, Value]:
        merged: dict[int, Value] = {}
        for k in iftrue.keys() | iffalse.keys():
            if k in iftrue and k in iffalse:
                t, f = iftrue[k], iffalse[k]
                merged[k] = t if t == f else ConditionalExpression(condsite, t, f)
            else:
                merged[k] = iftrue[k] if k in iftrue else iffalse[k]
        return merged

    def merge(self, other: InstructionState, condsite: ConditionalSite) -> InstructionState:
        merged_state = InstructionState()
        merged_state.regs = InstructionState._merge_dicts(condsite, self.regs, other.regs)
        merged_state.unique = InstructionState._merge_dicts(condsite, self.unique, other.unique)
        merged_state.ram = InstructionState._merge_dicts(condsite, self.ram, other.ram)
        merged_state.stack = InstructionState._merge_dicts(condsite, self.stack, other.stack)
        merged_state.used_arguments = self.used_arguments | other.used_arguments
        return merged_state

    def clear_after_callsite(self, arch: ArchRegisters) -> None:
        if self.last_callsite is None:
            return
        for arg in self.last_callsite.args.values():
            if not isinstance(arg, BinaryOp):
                continue
            if not isinstance(arg.left, Register) or not isinstance(arg.right, int):
                continue
            if arg.left.offset == arch.stackpointer:
                self.stack.pop(ctypes.c_int32(arg.right).value, None)
        for reg in list(self.regs.keys()):
            if reg not in arch.unaffected:
                del self.regs[reg]
        self.regs[arch.ret] = self.last_callsite
        self.last_callsite = None


class _FakeAddrSpace:
    def __init__(self, name: str):
        self.name = name


class _FakeVarnode:
    def __init__(self, space: _FakeAddrSpace, offset: int, size: int):
        self.space = space
        self.offset = offset
        self.size = size


@dataclass
class _UnfinishedConditionalSite:
    condition: BinaryOp
    goto_iftrue: int


class Engine:

    _BINARY_OP_SYMBOLS: ClassVar[dict[pypcode.OpCode, tuple[str, bool]]] = {
        pypcode.OpCode.INT_ADD: ("+", False),
        pypcode.OpCode.INT_MULT: ("*", False),
        pypcode.OpCode.INT_LEFT: ("<<", False),
        pypcode.OpCode.INT_RIGHT: (">>", False),
        pypcode.OpCode.INT_AND: ("&", False),
        pypcode.OpCode.INT_SUB: ("-", False),
        pypcode.OpCode.INT_XOR: ("^", False),
        pypcode.OpCode.INT_OR: ("|", False),
        pypcode.OpCode.INT_EQUAL: ("==", False),
        pypcode.OpCode.INT_SLESS: ("<", True),
        pypcode.OpCode.INT_LESS: ("<", False),
        pypcode.OpCode.INT_SLESSEQUAL: ("<=", True),
        pypcode.OpCode.INT_LESSEQUAL: ("<=", False),
        pypcode.OpCode.INT_NOTEQUAL: ("!=", False),
        pypcode.OpCode.BOOL_AND: ("&", False),
        pypcode.OpCode.BOOL_OR: ("|", False),
        pypcode.OpCode.BOOL_XOR: ("^", False),
    }

    def __init__(self, bin_func: BinaryFunction):
        self.project = bin_func.project
        self.bin_func = bin_func
        self.instructions_state: dict[int, InstructionState] = dict()
        self.current_inst: int = 0
        self.previous_marks: list[int] = list()
        self.callsites: list[CallSite] = []
        self.conditional_sites: list[ConditionalSite] = []
        self.memory_accesses: list[MemoryAccess] = []
        self.addr_to_codeflow_conditional_site: dict[int, ConditionalSite] = {}
        self.current_blk: FunctionBlock = FunctionBlock(0, self.bin_func)  # Temporal initialization
        self._unfinished_condsite: Optional[_UnfinishedConditionalSite] = None
        self._conditional_move_condition: Optional[ConditionalSite] = None
        self._first_stack_access: Optional[Register] = None
        self._return_values: Optional[set[Value]] = None

    def analyze(self) -> None:
        for current_addr in self.bin_func.code_flow_graph.traverse():
            blk = self.bin_func.blocks_dict_start_address[current_addr]
            parents = self.bin_func.code_flow_graph.get_parents(current_addr)
            self.previous_marks = [self.bin_func.blocks_dict[parent].last_instruction_addr for parent in parents]
            self._analyze_block(blk)

    @property
    def loops_dict_start_address(self) -> LoopsDict:
        return self.bin_func.loops_dict_start_address

    @property
    def loops_dict(self) -> LoopsDict:
        return self.bin_func.loops_dict

    @property
    def return_values(self) -> set[Value]:
        if self._return_values is not None:
            return self._return_values

        self._return_values = set()

        callsites_by_addr = {cs.addr: cs for cs in self.callsites}

        for blk in self.bin_func.return_blocks.values():
            if blk.last_instruction_addr in callsites_by_addr:
                self._return_values.add(callsites_by_addr[blk.last_instruction_addr])
                continue

            ret_val = self.instructions_state[blk.last_instruction_addr].regs.get(self.project.arch_regs.ret)
            if ret_val is None:
                continue

            if isinstance(ret_val, ConditionalExpression):
                self._return_values.update(ret_val.collect_values())
            else:
                self._return_values.add(ret_val)

        return self._return_values

    def _handle_binary_op(self, op: pypcode.PcodeOp):
        op_symbol, signed = self._BINARY_OP_SYMBOLS[op.opcode]
        left = self.handle_get(op.inputs[0])
        right = self.handle_get(op.inputs[1])

        if op.output is None:
            raise ValueError("Output of binary operation is None")

        self.handle_put(op.output, BinaryOp.create_binop(left, right, op_symbol, signed))

    def _analyze_block(self, blk: FunctionBlock):
        self.current_blk = blk
        current_address = blk.start

        while current_address < blk.end:
            for op in self.bin_func.opcodes[current_address].ops:
                Engine._OPCODE_HANDLERS[op.opcode](self, op)
            current_address += self.bin_func.opcodes[current_address].bytes_size

    def _get_block_and_state_from_mark(self, mark: int) -> tuple[FunctionBlock, InstructionState]:
        blk = self.bin_func.blocks_dict[mark]
        state = self.instructions_state[mark]
        return blk, state.goto_state.get(self.current_inst, state)

    def _handle_imark(self, op: pypcode.PcodeOp):
        self.current_inst = op.inputs[0].offset
        self._unfinished_condsite = None
        self._conditional_move_condition = None

        self._filter_loop_back_edges()
        self.instructions_state[self.current_inst] = self._compute_entry_state()

        if self.current_inst in self.loops_dict_start_address:
            self._clear_looped_registers()

        self.previous_marks = [self.current_inst]

    def _filter_loop_back_edges(self):
        if self.current_inst not in self.loops_dict_start_address:
            return

        loops = self.loops_dict[self.current_inst]
        if len(loops) == 2 and loops[0].start != loops[1].start:
            if loops[0].blocks <= loops[1].blocks:
                loops = [loops[0]]
            elif loops[1].blocks <= loops[0].blocks:
                loops = [loops[1]]

        self.previous_marks = [
            mark
            for mark in self.previous_marks
            if not any(self.bin_func.blocks_dict[mark].start in loop.blocks for loop in loops)
        ]

    def _compute_entry_state(self) -> InstructionState:
        if not self.previous_marks:
            return InstructionState()

        if len(self.previous_marks) == 1:
            _, state = self._get_parent_state(self.previous_marks[0])
            return state

        parent_contexts = [self._get_parent_state(mark) for mark in self.previous_marks]
        return self._merge_parent_contexts(parent_contexts)

    def _get_parent_state(self, mark: int) -> tuple[FunctionBlock, InstructionState]:
        blk, state = self._get_block_and_state_from_mark(mark)
        state_copy = state.copy()
        state_copy.clear_after_callsite(self.project.arch_regs)
        return blk, state_copy

    def _merge_parent_contexts(self, parent_contexts: list[tuple[FunctionBlock, InstructionState]]) -> InstructionState:
        current_blk, current_state = parent_contexts[0]
        for next_blk, next_state in parent_contexts[1:]:
            common_ancestor_addr = self.bin_func.common_ancestor(current_blk, next_blk)
            if common_ancestor_addr is not None:
                common_condsite = self.addr_to_codeflow_conditional_site.get(common_ancestor_addr)
                if common_condsite:
                    if self.bin_func.is_ancestor(current_blk.start, common_condsite.iffalse):
                        current_state = current_state.merge(next_state, common_condsite)
                    else:
                        current_state = next_state.merge(current_state, common_condsite)
            current_blk = next_blk
        return current_state

    def _clear_looped_registers(self):
        for loop in self.loops_dict[self.current_inst]:
            for blk in loop.blocks:
                current_blk = self.bin_func.blocks_dict[blk]
                current_address = current_blk.start
                while current_address < current_blk.end:
                    for op in self.bin_func.opcodes[current_address].ops:
                        if op.output is None or op.output.space.name != "register":
                            continue

                        self.instructions_state[self.current_inst].regs.pop(op.output.offset, None)
                        self.instructions_state[self.current_inst].used_arguments.add(op.output.offset)
                    current_address += self.bin_func.opcodes[current_address].bytes_size

    def _handle_copy(self, op: pypcode.PcodeOp):
        self.handle_put(op.output, self.handle_get(op.inputs[0]))

    def _handle_store(self, op: pypcode.PcodeOp):
        space = op.inputs[0].getSpaceFromConst().name
        offset = self.handle_get(op.inputs[1])
        val = self.handle_get(op.inputs[2])

        if space != "ram":
            raise NotImplementedError(f"STORE to space '{space}' is not implemented yet.")

        if isinstance(offset, int):
            self.instructions_state[self.current_inst].ram[offset] = val
            return

        if not isinstance(offset, BinaryOp):
            self.memory_accesses.append(MemoryAccess(self.current_inst, offset, 0, MemoryAccessType.STORE, val))
            return

        left, right = offset.left, offset.right
        sp_offset = self._extract_stack_offset(offset)
        if sp_offset is not None:
            self.instructions_state[self.current_inst].stack[sp_offset] = val
            return

        self.memory_accesses.append(MemoryAccess(self.current_inst, left, right, MemoryAccessType.STORE, val))

    def _extract_stack_offset(self, offset: Value) -> int | None:
        """Return signed sp-relative offset for a `sp +/- int` BinaryOp, else None."""
        if not isinstance(offset, BinaryOp) or not isinstance(offset.right, int):
            return None
        if not isinstance(offset.left, Register) or offset.left.offset != self.project.arch_regs.stackpointer:
            return None
        if offset.op == "+":
            return ctypes.c_int32(offset.right).value
        if offset.op == "-":
            return -ctypes.c_int32(offset.right).value
        return None

    def _handle_int_2comp(self, op: pypcode.PcodeOp):
        val = self.handle_get(op.inputs[0])

        self.handle_put(op.output, BinaryOp.create_binop(0, val, "-"))

    def _handle_call(self, op: pypcode.PcodeOp):
        self._handle_callind(op)

    def _create_callsite(self, target: Value) -> CallSite:
        resolved_target = self._extract_target(target)
        args = self._collect_call_arguments()

        callsite = CallSite(self.current_inst, resolved_target, frozendict(args))
        self._register_callsite(callsite)

        return callsite

    def _handle_callind(self, op: pypcode.PcodeOp):
        target = self.handle_get(op.inputs[0])

        self._create_callsite(target)

    def _handle_int_zext(self, op: pypcode.PcodeOp):
        # Assuming zext(X) == X for now.
        self.handle_put(op.output, self.handle_get(op.inputs[0]))

    def _handle_subpiece(self, op: pypcode.PcodeOp):
        # Assuming X = SUBPIECE(X, N) for now
        self.handle_put(op.output, self.handle_get(op.inputs[0]))

    def _is_in_loop(self, addr: int, loop) -> bool:
        # `loop.blocks` holds block START addresses, but a branch target can land
        # anywhere inside a block (e.g., the next ARM instruction in conditional
        # execution patterns). Map the address back to its containing block first.
        blk = self.bin_func.blocks_dict.get(addr)
        return blk is not None and blk.start in loop.blocks

    def _create_condsite(self, condition: BinaryOp, goto_iftrue: int, goto_iffalse: int) -> ConditionalSite:
        condsite = ConditionalSite(self.current_inst, condition, goto_iftrue, goto_iffalse)
        self.conditional_sites.append(condsite)
        if goto_iftrue != CBRANCH_SKIP_ADDR:
            self.addr_to_codeflow_conditional_site[self.current_blk.start] = condsite

        loops = self.loops_dict.get(self.current_inst, None)
        if loops is not None and isinstance(condition, BinaryOp):
            for loop in loops:
                if not self._is_in_loop(goto_iftrue, loop):
                    loop.exit_conditions[self.current_inst] = condition
                elif not self._is_in_loop(goto_iffalse, loop):
                    loop.exit_conditions[self.current_inst] = condition.negate()

        return condsite

    def _handle_branch(self, op: pypcode.PcodeOp):
        goto_addr = self.handle_get(op.inputs[0])
        assert isinstance(goto_addr, int)

        if goto_addr < self.bin_func.start or goto_addr >= self.bin_func.end:
            self._create_callsite(goto_addr)
            return

        if self._unfinished_condsite is None:
            return

        self._create_condsite(self._unfinished_condsite.condition, self._unfinished_condsite.goto_iftrue, goto_addr)

    def _handle_cbranch(self, op: pypcode.PcodeOp):
        goto_iftrue = self.handle_get(op.inputs[0])
        goto_iffalse = self.bin_func._next_address(self.current_inst)
        condition = self.handle_get(op.inputs[1])

        assert isinstance(goto_iftrue, int)

        if isinstance(condition, int):  # Sometimes the result is known at analysis time, for example LL/SC instructions
            return

        # Conditions are typically comparison BinaryOps, but composite booleans
        # (BOOL_AND/BOOL_OR/!()) and merged-state ConditionalExpressions can also
        # drive CBRANCH on ARM. (Anything non-int reachable here.)
        assert not isinstance(condition, int)

        if goto_iftrue == CBRANCH_SKIP_ADDR:
            self._conditional_move_condition = self._create_condsite(condition, goto_iftrue, goto_iffalse)
            return

        if goto_iffalse == goto_iftrue:
            # When the IMARK covers a single ARM instruction this is ARM conditional execution
            # (MOVNE, ADDEQ, ...); when it covers two (branch + delay slot) it's a MIPS
            # branch-likely whose delay slot is annulled on the not-taken path.
            imark = self.bin_func.opcodes[self.current_inst].ops[0]
            if len(imark.inputs) == 1:
                self._conditional_move_condition = self._create_condsite(condition, goto_iftrue, goto_iffalse)
                return
            self.instructions_state[self.current_inst].goto_state[goto_iftrue] = self.instructions_state[
                self.current_inst
            ].copy()
            self._unfinished_condsite = _UnfinishedConditionalSite(condition, goto_iftrue)
            return

        self._create_condsite(condition, goto_iftrue, goto_iffalse)

    def _do_nothing(self, op: pypcode.PcodeOp):
        pass

    def _handle_int_carry(self, op: pypcode.PcodeOp):
        # INT_CARRY(a, b) = 1 iff (a + b) overflows past 0xFFFFFFFF.
        # For constant b > 0: (a + b) > MAX ⟺ a >= (-b) & MAX. This direct
        # form lets later equality-with-zero and comparison-combining rules
        # produce clean conditions (e.g. ARM CMN-then-BHI lifts to `a > c`).
        a = self.handle_get(op.inputs[0])
        b = self.handle_get(op.inputs[1])
        if isinstance(a, int) and isinstance(b, int):
            self.handle_put(op.output, 1 if (a + b) > 0xFFFFFFFF else 0)
            return
        if isinstance(b, int) or isinstance(a, int):
            const, expr = (b, a) if isinstance(b, int) else (a, b)
            self.handle_put(op.output, 0 if const == 0 else BinaryOp(expr, (-const) & 0xFFFFFFFF, ">="))
            return
        # Symbolic both sides: ~a < b unsigned is equivalent.
        self.handle_put(op.output, BinaryOp(UnaryOp(a, "~"), b, "<"))

    def _handle_branchind(self, op: pypcode.PcodeOp):
        target = self.handle_get(op.inputs[0])

        self._create_callsite(target)

    def _handle_bool_negate(self, op: pypcode.PcodeOp):
        bool_expr = self.handle_get(op.inputs[0])

        if isinstance(bool_expr, int):
            self._handle_int_negate(op)
            return

        if isinstance(bool_expr, BinaryOp) and bool_expr.op in {"==", "!=", "<", "<=", ">", ">="}:
            self.handle_put(op.output, bool_expr.negate())
            return

        # Composite booleans (e.g. BOOL_AND/BOOL_OR results, double-negation, etc.)
        # don't have a simple negated form — wrap in a logical-not UnaryOp.
        self.handle_put(op.output, UnaryOp(bool_expr, "!"))

    def _handle_int_negate(self, op: pypcode.PcodeOp):
        int_expr = self.handle_get(op.inputs[0])
        if isinstance(int_expr, int):
            self.handle_put(op.output, ~int_expr & 0xFFFFFFFF)
            return
        self.handle_put(op.output, UnaryOp(int_expr, "~"))

    def _handle_int_sext(self, op: pypcode.PcodeOp):
        # TODO: For now assuming X = sext(X)
        self.handle_put(op.output, self.handle_get(op.inputs[0]))

    def _handle_load(self, op: pypcode.PcodeOp):
        space = op.inputs[0].getSpaceFromConst().name
        if space != "ram":
            raise NotImplementedError(f"LOAD to space '{space}' is not implemented yet.")
        offset = self.handle_get(op.inputs[1])
        self.handle_put(op.output, self._resolve_ram_load(offset))

    def _resolve_ram_load(self, offset: Value) -> Value:
        if isinstance(offset, (int, UnaryOp)):
            return UnaryOp(offset, "*")

        if not isinstance(offset, BinaryOp):
            return self._record_load(offset, 0)

        sp_offset = self._extract_stack_offset(offset)
        if sp_offset is not None:
            return self._resolve_stack_load(ctypes.c_uint32(sp_offset).value)
        return self._record_load(offset.left, offset.right)

    def _record_load(self, base: Value, offset: Value) -> MemoryAccess:
        res = MemoryAccess(self.current_inst, base, offset, MemoryAccessType.LOAD)
        self.memory_accesses.append(res)
        return res

    def _resolve_stack_load(self, right: Value) -> Value:
        assert isinstance(right, int)
        arch = self.project.arch_regs
        state = self.instructions_state[self.current_inst]
        signed_value = ctypes.c_int32(right).value

        if signed_value >= arch.stack_argument_offset:
            return Arg(signed_value // arch.pointer_size)

        res = state.stack.get(signed_value)
        if res is None:
            assert self._first_stack_access is not None
            res = MemoryAccess(
                self.current_inst, self._first_stack_access, ctypes.c_uint32(right).value, MemoryAccessType.LOAD
            )
            state.stack[signed_value] = res
        return res

    def _handle_get_register(self, offset: int) -> Value:
        state = self.instructions_state[self.current_inst]
        arch = self.project.arch_regs

        reg = state.regs.get(offset, None)
        if reg is not None:
            return reg

        res: Register | Arg
        if offset in arch.rev_arguments and state.last_callsite is None and offset not in state.used_arguments:
            res = Arg(arch.rev_arguments[offset])
        else:
            res = Register(offset, self.current_inst, self.project)
            if offset == arch.stackpointer and self._first_stack_access is None:
                self._first_stack_access = res

        state.regs[offset] = res
        return res

    def _handle_get_const(self, offset: int) -> int:
        return offset

    def _handle_get_unique(self, offset: int) -> Value | None:
        return self.instructions_state[self.current_inst].unique.get(offset)

    def handle_get(self, input: pypcode.Varnode | _FakeVarnode) -> Value:
        return Engine._GET_HANDLERS[input.space.name](self, input.offset)

    def _handle_put_register(self, offset: int, val: Value):
        if self._conditional_move_condition is not None:
            prior = self._handle_get_register(offset)
            if prior != val:
                # When both branches of a conditional move agree, the register is
                # unchanged regardless of the condition (e.g. ARM MOVLS R0, R0).
                val = ConditionalExpression(self._conditional_move_condition, prior, val)
        self.instructions_state[self.current_inst].regs[offset] = val

    def _handle_put_unique(self, offset: int, val: Value):
        self.instructions_state[self.current_inst].unique[offset] = val

    def handle_put(self, output: pypcode.Varnode | None, val: Value):
        if output is None:
            return
        Engine._PUT_HANDLERS[output.space.name](self, output.offset, val)

    def _extract_target(self, target: Value) -> Value:
        if self.project.arch_regs.does_isa_switches and isinstance(target, BinaryOp):
            target = target.right

        return target

    def _register_callsite(self, callsite: CallSite) -> None:
        self.callsites.append(callsite)
        self.instructions_state[self.current_inst].last_callsite = callsite

    def _collect_call_arguments(self) -> dict[int, Value]:
        state = self.instructions_state[self.current_inst]
        arch = self.project.arch_regs

        args = {arg_num: state.regs[reg] for arg_num, reg in arch.arguments.items() if reg in state.regs}

        current_stack = state.regs.get(arch.stackpointer, None)
        if (
            isinstance(current_stack, BinaryOp)
            and isinstance(current_stack.right, int)
            and (len(args) == len(arch.arguments) or len(args) == 0)
        ):
            # If SP folded back to the entry-time Register (no offset), there are no
            # stack args. Only the BinaryOp(sp_reg, signed_offset, "+") form indicates
            # a frame where outgoing stack args may live.
            stack_argument_offset = ctypes.c_int32(current_stack.right + arch.stack_argument_offset).value
            arg_num = len(arch.arguments)

            while stack_argument_offset in state.stack:
                val = state.stack[stack_argument_offset]
                # Skip callee-save spills: a stack slot still holding the entry-time
                # value of a register (the only Registers stamped at bin_func.start) is
                # not a stack-passed argument but a PUSH'd save from the prologue.
                if isinstance(val, Register) and val.address == self.bin_func.start:
                    break
                args[arg_num] = val
                stack_argument_offset += arch.pointer_size
                arg_num += 1

        max_reg_arg = min(max(args.keys(), default=0), len(arch.arguments))

        for arg_num, _ in arch.arguments.items():
            if arg_num not in args and arg_num < max_reg_arg:
                args[arg_num] = self.handle_get(_FakeVarnode(_FakeAddrSpace("register"), arch.arguments[arg_num], 4))

        return args

    # Class-level dispatch tables. Methods referenced here must be defined above.
    _OPCODE_HANDLERS: ClassVar[dict[pypcode.OpCode, Callable]] = {
        pypcode.OpCode.INT_ADD: _handle_binary_op,
        pypcode.OpCode.INT_MULT: _handle_binary_op,
        pypcode.OpCode.INT_LEFT: _handle_binary_op,
        pypcode.OpCode.INT_RIGHT: _handle_binary_op,
        pypcode.OpCode.INT_AND: _handle_binary_op,
        pypcode.OpCode.INT_SUB: _handle_binary_op,
        pypcode.OpCode.INT_XOR: _handle_binary_op,
        pypcode.OpCode.INT_OR: _handle_binary_op,
        pypcode.OpCode.INT_EQUAL: _handle_binary_op,
        pypcode.OpCode.INT_SLESS: _handle_binary_op,
        pypcode.OpCode.INT_LESS: _handle_binary_op,
        pypcode.OpCode.INT_SLESSEQUAL: _handle_binary_op,
        pypcode.OpCode.INT_LESSEQUAL: _handle_binary_op,
        pypcode.OpCode.INT_NOTEQUAL: _handle_binary_op,
        pypcode.OpCode.COPY: _handle_copy,
        pypcode.OpCode.STORE: _handle_store,
        pypcode.OpCode.LOAD: _handle_load,
        pypcode.OpCode.IMARK: _handle_imark,
        pypcode.OpCode.CALL: _handle_call,
        pypcode.OpCode.CALLIND: _handle_callind,
        pypcode.OpCode.CALLOTHER: _do_nothing,  # TODO: Think if required, example is MIPS `rdhwr` in `sshd` `fileno` Function
        pypcode.OpCode.INT_CARRY: _handle_int_carry,
        pypcode.OpCode.INT_SCARRY: _do_nothing,
        pypcode.OpCode.INT_SBORROW: _do_nothing,
        pypcode.OpCode.BOOL_AND: _handle_binary_op,
        pypcode.OpCode.BOOL_OR: _handle_binary_op,
        pypcode.OpCode.BOOL_XOR: _handle_binary_op,
        pypcode.OpCode.CBRANCH: _handle_cbranch,
        pypcode.OpCode.BRANCH: _handle_branch,
        pypcode.OpCode.BRANCHIND: _handle_branchind,
        pypcode.OpCode.RETURN: _do_nothing,
        pypcode.OpCode.INT_2COMP: _handle_int_2comp,
        pypcode.OpCode.BOOL_NEGATE: _handle_bool_negate,
        pypcode.OpCode.INT_NEGATE: _handle_int_negate,
        pypcode.OpCode.INT_SEXT: _handle_int_sext,
        pypcode.OpCode.INT_ZEXT: _handle_int_zext,
        pypcode.OpCode.SUBPIECE: _handle_subpiece,
    }

    _PUT_HANDLERS: ClassVar[dict[str, Callable]] = {
        "register": _handle_put_register,
        "unique": _handle_put_unique,
    }

    _GET_HANDLERS: ClassVar[dict[str, Callable]] = {
        "register": _handle_get_register,
        "const": _handle_get_const,
        "unique": _handle_get_unique,
        "ram": _handle_get_const,
    }
