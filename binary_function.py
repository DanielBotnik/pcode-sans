from __future__ import annotations
from typing import TYPE_CHECKING

import pypcode

from dataclasses import dataclass
from cfg import CodeFlowGraph

if TYPE_CHECKING:
    from engine_types import BinaryOp
from project import Project

from collections import deque


@dataclass
class AddressOpcodes:
    ops: list[pypcode.PcodeOp]
    bytes_size: int

    def __repr__(self):
        return f"{self.__class__.__name__}(bytes_size={self.bytes_size}, {len(self.ops)} OpCodes)"


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

        self.loops: dict[int, Loop] = dict()

        self.code_flow_grpah: CodeFlowGraph = CodeFlowGraph()

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

    def _init_function_nodes(self):

        def add_address_to_visit(addr):
            if addr not in visited_addresses:
                address_to_visit.append(addr)

        visited_addresses = set()
        address_to_visit = deque()
        address_to_visit.append(self.start)
        self.code_flow_grpah.add_block(self.start)  # Must be for single block functions

        while len(address_to_visit) != 0:
            current_vistied_address = address_to_visit.popleft()
            if current_vistied_address in visited_addresses:
                continue
            visited_addresses.add(current_vistied_address)

            # This catches the case where an entire block have been created, but later due to a jmp
            # a new block starts in the middle of the full block, meaning it should be split into
            # two different blocks.
            if current_vistied_address in self.blocks_dict:
                the_blk = self.blocks_dict[current_vistied_address]

                blk_a = FunctionBlock(the_blk.start, self, current_vistied_address - 1)
                blk_b = FunctionBlock(current_vistied_address, self, end=the_blk.end)

                self.blocks_dict_start_address[the_blk.start] = blk_a
                for addr in list(self.blocks_dict.keys()):
                    if blk_a.start <= addr <= blk_a.end:
                        self.blocks_dict[addr] = blk_a

                self.blocks_dict_start_address[current_vistied_address] = blk_b
                for addr in list(self.blocks_dict.keys()):
                    if blk_b.start <= addr <= blk_b.end:
                        self.blocks_dict[addr] = blk_b

                first_node = self.code_flow_grpah.addr_to_vertex_id[the_blk.start]
                second_node = self.code_flow_grpah.addr_to_vertex_id[current_vistied_address]

                targets = [e.target for e in self.code_flow_grpah.graph.es.select(_source=first_node)]
                self.code_flow_grpah.graph.delete_edges([(first_node, t) for t in targets])

                for t in targets:
                    if not self.code_flow_grpah.graph.are_adjacent(second_node, t):
                        self.code_flow_grpah.graph.add_edge(second_node, t)

                if not self.code_flow_grpah.graph.are_adjacent(first_node, second_node):
                    self.code_flow_grpah.graph.add_edge(first_node, second_node)

                continue

            current_address = current_vistied_address
            current_blk = FunctionBlock(current_vistied_address, self)
            self.blocks_dict_start_address[current_vistied_address] = current_blk
            block_reached_end = False

            while block_reached_end == False:

                if current_address in self.blocks_dict:
                    self.code_flow_grpah.add_edge(current_blk.start, current_address)
                    current_blk.end = current_address - 1
                    break

                self.blocks_dict[current_address] = current_blk

                for op in self.opcodes[current_address].ops:
                    if op.opcode == pypcode.OpCode.CBRANCH:

                        self.code_flow_grpah.add_edge(current_blk.start, op.inputs[0].offset)
                        add_address_to_visit(op.inputs[0].offset)

                        # Sometimes the next address is the jump address
                        # future `OpCode.BRANCH` will handle that case
                        # TODO: How will this handle conditional sites
                        if op.inputs[0].offset == self._next_address(current_address):
                            continue

                        self.code_flow_grpah.add_edge(current_blk.start, self._next_address(current_address))
                        add_address_to_visit(self._next_address(current_address))

                        current_blk.end = self._next_address(current_address) - 1
                        block_reached_end = True

                    elif op.opcode == pypcode.OpCode.BRANCH:
                        self.code_flow_grpah.add_edge(current_blk.start, op.inputs[0].offset)
                        add_address_to_visit(op.inputs[0].offset)
                        current_blk.end = self._next_address(current_address) - 1
                        block_reached_end = True

                    elif op.opcode == pypcode.OpCode.BRANCHIND:
                        current_blk.end = self._next_address(current_address) - 1
                        block_reached_end = True

                    elif op.opcode == pypcode.OpCode.RETURN:
                        current_blk.end = self._next_address(current_address) - 1
                        block_reached_end = True

                    elif op.opcode == pypcode.OpCode.IMARK:
                        current_blk._last_instruction_addr = op.inputs[0].offset

                current_address += self.opcodes[current_address].bytes_size

    def _init_loops(self):
        for loop in self.code_flow_grpah.get_loops():
            self.loops[loop[0]] = Loop(start=loop[0], blocks=set(loop))

    def _next_address(self, current_address):
        return current_address + self.opcodes[current_address].bytes_size

    def is_ancestor(self, addr1: int, addr2: int) -> bool:
        return self.code_flow_grpah.is_ancestor(addr1, addr2)

    def common_ancestor(self, addr1: int, addr2: int) -> int:
        return self.code_flow_grpah.first_common_ancestor(addr1, addr2)


class FunctionBlock:

    def __init__(self, start: int, function: BinaryFunction, end: int = None):
        self.start = start
        self.end = end
        self.function = function

        self._last_instruction_addr: int = None

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
    blocks: set[int]
    exit_conditions: set[BinaryOp] = None
