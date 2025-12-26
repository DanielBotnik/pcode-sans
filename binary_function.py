from __future__ import annotations
from typing import TYPE_CHECKING

import pypcode

from dataclasses import dataclass, field
from cfg import CodeFlowGraph

if TYPE_CHECKING:
    from engine_types import BinaryOp, LoopsDict
from project import Project

from collections import deque


@dataclass
class AddressOpcodes:
    ops: list[pypcode.PcodeOp]
    bytes_size: int

    def __repr__(self):
        return f"{self.__class__.__name__}(bytes_size={self.bytes_size}, {len(self.ops)} OpCodes)"


@dataclass
class _VisitedState:
    visited_addresses: set[int] = field(default_factory=set)
    address_to_visit: deque[int] = field(default_factory=deque)


class BinaryFunction:

    def __init__(self, start: int, code: bytes, project: Project):
        self.start = start
        self.end = start + len(code)
        self.code = code
        self.project = project
        self.opcodes: dict[int, AddressOpcodes] = dict()

        self.blocks_dict: dict[int, FunctionBlock] = {}
        self.blocks_dict_start_address: dict[int, FunctionBlock] = {}
        self.return_blocks: set[FunctionBlock] = set()

        self.loops_dict: LoopsDict = dict()
        self.loops_dict_start_address: LoopsDict = dict()

        self.code_flow_grpah: CodeFlowGraph = CodeFlowGraph()

        self.__visited_state: _VisitedState = _VisitedState()
        self.__handlers = {
            pypcode.OpCode.CBRANCH: self._handle_cbranch,
            pypcode.OpCode.BRANCH: self._handle_branch,
            pypcode.OpCode.BRANCHIND: self._handle_branchind,
            pypcode.OpCode.RETURN: self._handle_branchind,
            pypcode.OpCode.IMARK: self._handle_imark,
        }

        self._init_opcodes()
        self._init_function_nodes()
        self._init_loops()

    def _init_opcodes(self):
        opcodes = self.project.context.translate(self.code, self.start).ops

        current_address = None
        current_size = None
        last_index = 0
        for idx, op in enumerate(opcodes):
            if op.opcode == pypcode.OpCode.IMARK:
                if current_address is not None:
                    self.opcodes[current_address] = AddressOpcodes(opcodes[last_index:idx], current_size)

                last_index = idx
                current_address = op.inputs[0].offset
                current_size = sum([x.size for x in op.inputs])
        self.opcodes[current_address] = AddressOpcodes(opcodes[last_index:], current_size)

    def __fix_splited_block(self, blk_addr: int, blk: FunctionBlock):
        self.blocks_dict_start_address[blk_addr] = blk
        for addr in list(self.blocks_dict.keys()):
            if blk.start <= addr <= blk.end:
                self.blocks_dict[addr] = blk

    def _split_block(self, current_address: int):
        the_blk = self.blocks_dict[current_address]

        blk_a = FunctionBlock(the_blk.start, self, current_address - 1)
        blk_b = FunctionBlock(current_address, self, end=the_blk.end)

        self.__fix_splited_block(the_blk.start, blk_a)
        self.__fix_splited_block(current_address, blk_b)

        first_node = self.code_flow_grpah.addr_to_vertex_id[the_blk.start]
        second_node = self.code_flow_grpah.addr_to_vertex_id[current_address]

        targets = [e.target for e in self.code_flow_grpah.graph.es.select(_source=first_node)]
        self.code_flow_grpah.graph.delete_edges([(first_node, t) for t in targets])

        for t in targets:
            if not self.code_flow_grpah.graph.are_adjacent(second_node, t):
                self.code_flow_grpah.graph.add_edge(second_node, t)

        if not self.code_flow_grpah.graph.are_adjacent(first_node, second_node):
            self.code_flow_grpah.graph.add_edge(first_node, second_node)

    def _add_address_to_visit(self, addr):
        if addr not in self.__visited_state.visited_addresses:
            self.__visited_state.address_to_visit.append(addr)

    def _handle_cbranch(self, op: pypcode.PcodeOp, addr: int, blk: FunctionBlock):
        branch_addr = op.inputs[0].offset
        if branch_addr == 2:  # This means skip insturctions
            return

        self.code_flow_grpah.add_edge(blk.start, branch_addr)
        self._add_address_to_visit(branch_addr)

        # Sometimes the next address is the jump address
        # future `OpCode.BRANCH` will handle that case
        if branch_addr == self._next_address(addr):
            return

        self.code_flow_grpah.add_edge(blk.start, self._next_address(addr))
        self._add_address_to_visit(self._next_address(addr))

        blk.end = self._next_address(addr) - 1
        return True

    def _handle_branch(self, op: pypcode.PcodeOp, addr: int, blk: FunctionBlock):
        branch_addr = op.inputs[0].offset
        if self.start < branch_addr <= self.end:  # Jumping outside of the function
            self.code_flow_grpah.add_edge(blk.start, branch_addr)
            self._add_address_to_visit(branch_addr)

        blk.end = self._next_address(addr) - 1
        return True

    def _handle_branchind(self, op: pypcode.PcodeOp, addr: int, blk: FunctionBlock):
        blk.end = self._next_address(addr) - 1
        return True

    def _handle_imark(self, op: pypcode.PcodeOp, addr: int, blk: FunctionBlock):
        blk._last_instruction_addr = op.inputs[0].offset
        return False

    def _iterate_address_instructions(self, addr: int, blk: FunctionBlock):
        is_last_address = False

        for op in self.opcodes[addr].ops:
            handler = self.__handlers.get(op.opcode)
            if handler is not None:
                is_last_address = handler(op, addr, blk)

        return is_last_address

    def _iterate_block_instructions(self, addr: int, blk: FunctionBlock):
        while True:
            if addr in self.blocks_dict:  # A block was previously generated from a jump
                self.code_flow_grpah.add_edge(blk.start, addr)
                blk.end = addr - 1
                break

            self.blocks_dict[addr] = blk

            is_last_address = self._iterate_address_instructions(addr, blk)
            if is_last_address:
                break

            addr += self.opcodes[addr].bytes_size

    def _init_function_nodes(self):
        self.__visited_state.address_to_visit.append(self.start)
        self.code_flow_grpah.add_block(self.start)  # Must be for single block functions

        while len(self.__visited_state.address_to_visit) != 0:
            current_address = self.__visited_state.address_to_visit.popleft()
            if current_address in self.__visited_state.visited_addresses:
                continue
            self.__visited_state.visited_addresses.add(current_address)

            # This catches the case where an entire block have been created, but later due to a jmp
            # a new block starts in the middle of the full block, meaning it should be split into
            # two different blocks.
            if current_address in self.blocks_dict:
                self._split_block(current_address)
                continue

            current_blk = FunctionBlock(current_address, self)
            self.blocks_dict_start_address[current_address] = current_blk
            self._iterate_block_instructions(current_address, current_blk)

    def _init_loops(self):
        for loop in self.code_flow_grpah.get_loops():
            loop = Loop(start=loop[0], blocks=set(loop))
            for blk_addr in loop.blocks:
                for addr in range(blk_addr, self.blocks_dict[blk_addr].end + 1, self.opcodes[blk_addr].bytes_size):
                    if addr not in self.loops_dict:
                        self.loops_dict[addr] = [loop]
                    else:
                        self.loops_dict[addr].append(loop)

            if loop.start not in self.loops_dict_start_address:
                self.loops_dict_start_address[loop.start] = [loop]
            else:
                self.loops_dict_start_address[loop.start].append(loop)

    def _next_address(self, current_address):
        return current_address + self.opcodes[current_address].bytes_size

    def is_ancestor(self, addr1: int, addr2: int) -> bool:
        return self.code_flow_grpah.is_ancestor(addr1, addr2)

    def common_ancestor(self, addr1: int, addr2: int) -> int:
        return self.code_flow_grpah.first_common_ancestor(addr1, addr2)


class FunctionBlock:

    def __init__(self, start: int, function: BinaryFunction, end: int = -1):
        self.start = start
        self.end = end
        self.function = function

        self._last_instruction_addr: int | None = None

    @property
    def last_instruction_addr(self) -> int:
        """
        When FunctionBlock is split into two blocks, the last instruction that was
        derived from the IMARK may no longer be the last instruction in the block, so its invalid.
        This property calculates the last instruction address on demand and caches it.
        """

        if self._last_instruction_addr is not None:
            return self._last_instruction_addr

        addr = self.start
        while True:
            next_addr = addr + self.function.opcodes[addr].bytes_size
            if next_addr > self.end:
                self._last_instruction_addr = addr
                return addr
            addr = next_addr


@dataclass
class Loop:
    start: int
    blocks: set[int] = field(default_factory=set)
    exit_conditions: dict[int, BinaryOp] = field(default_factory=dict)
