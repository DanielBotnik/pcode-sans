from collections import deque
from typing import Iterator
from igraph import Graph

# TODO: Write tests for this.


class CodeFlowGraph:
    def __init__(self):
        self.graph = Graph(directed=True)
        self.addr_to_vertex_id: dict[int, int] = dict()

    def add_block(self, addr: int) -> int:
        if addr in self.addr_to_vertex_id:
            return self.addr_to_vertex_id[addr]

        vertex_id: int = self.graph.vcount()
        self.graph.add_vertex()
        self.graph.vs[vertex_id]["addr"] = addr

        self.addr_to_vertex_id[addr] = vertex_id
        return vertex_id

    def add_edge(self, src_addr: int, dst_addr: int) -> None:
        src_vertex_id = self.add_block(src_addr)
        dst_addr_id = self.add_block(dst_addr)

        self.graph.add_edge(src_vertex_id, dst_addr_id)

    def add_edges(self, src_addr: int, dst_addrs: list[int]) -> None:
        for dst_addr in dst_addrs:
            self.add_edge(src_addr, dst_addr)

    def get_parnets(self, addr: int) -> list[int]:
        vertex_id = self.addr_to_vertex_id[addr]
        parent_vertex_ids = self.graph.predecessors(vertex_id)
        parent_addrs = [self.graph.vs[vid]["addr"] for vid in parent_vertex_ids]
        return parent_addrs

    def print_cfg(self):
        """Print the CFG vertices and edges, optionally plot it."""
        print(f"{len(self.graph.vs)} Vertices:")
        for v in self.graph.vs:
            addr = v["addr"] if "addr" in v.attributes() else v.index
            print(f"Vertex {v.index}: addr={hex(addr) if isinstance(addr,int) else addr}")

        print(f"\n{len(self.graph.es)} Edges:")
        for e in self.graph.es:
            src = self.graph.vs[e.source]["addr"] if "addr" in self.graph.vs[e.source].attributes() else e.source
            dst = self.graph.vs[e.target]["addr"] if "addr" in self.graph.vs[e.target].attributes() else e.target
            print(f"{hex(src) if isinstance(src,int) else src} -> {hex(dst) if isinstance(dst,int) else dst}")

    def traverse(self):
        """
        Generator that yields nodes such that each node is visited
        only after all its parents have been visited.
        """
        g = self.graph

        # Compute indegrees (number of unvisited parents)
        indegrees = {v.index: len(g.predecessors(v.index)) for v in g.vs}

        # Start with nodes that have no parents
        queue = deque([v.index for v in g.vs if indegrees[v.index] == 0])
        visited_count = 0

        while queue:
            vid = queue.popleft()
            addr = g.vs[vid]["addr"]
            yield addr
            visited_count += 1

            # Decrease indegree for children
            for succ in g.successors(vid):
                indegrees[succ] -= 1
                if indegrees[succ] == 0:
                    queue.append(succ)

        # Detect cycles (optional but useful)
        if visited_count != g.vcount():
            raise ValueError("Graph has a cycle — cannot fully traverse topologically.")

    def first_common_ancestor(self, addr1: int, addr2: int) -> int:
        anc_u = set(self.graph.subcomponent(self.addr_to_vertex_id[addr1], mode="IN"))
        anc_v = set(self.graph.subcomponent(self.addr_to_vertex_id[addr2], mode="IN"))

        commons = anc_u & anc_v

        vertex_idx = min(
            commons,
            key=lambda a: max(
                self.graph.distances(a, self.addr_to_vertex_id[addr1])[0],
                self.graph.distances(a, self.addr_to_vertex_id[addr2])[0],
            ),
        )

        return self.graph.vs[vertex_idx]["addr"]

    def is_ancestor(self, addr1: int, addr2: int) -> bool:
        vertex1 = self.addr_to_vertex_id[addr1]
        vertex2 = self.addr_to_vertex_id[addr2]

        return vertex1 in self.graph.subcomponent(vertex2, mode="OUT")
