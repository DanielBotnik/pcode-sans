from binary_function import BinaryFunction
from cfg import CodeFlowGraph
from engine_types import ConditionalSite
from pcode_engine import Engine


def verify_blocks_dict(bin_func: BinaryFunction):
    for blk in bin_func.blocks_dict_start_address.values():
        for addr in range(blk.start, blk.end, 4):
            if addr in bin_func.blocks_dict:
                assert bin_func.blocks_dict[addr] == blk


def verify_cfg_equal(cfg1: CodeFlowGraph, cfg2: CodeFlowGraph):
    assert cfg1.graph.vcount() == cfg2.graph.vcount()
    assert cfg1.graph.ecount() == cfg2.graph.ecount()

    edges1 = set()
    for e in cfg1.graph.es:
        src = cfg1.graph.vs[e.source]["addr"]
        dst = cfg1.graph.vs[e.target]["addr"]
        edges1.add((src, dst))

    edges2 = set()
    for e in cfg2.graph.es:
        src = cfg2.graph.vs[e.source]["addr"]
        dst = cfg2.graph.vs[e.target]["addr"]
        edges2.add((src, dst))

    assert edges1 == edges2


def get_condsite_by_addr(engine: Engine, addr: int) -> ConditionalSite:
    for condsite in engine.conditional_sites:
        if condsite.addr == addr:
            return condsite
