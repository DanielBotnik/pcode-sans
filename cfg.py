from collections import deque
from functools import lru_cache
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
        Traverse the graph starting from vertex 0.
        A node is yielded only when all its parents have been visited.
        If not all parents are visited, push the missing parents first.
        """
        g = self.graph
        cycles = self._get_loop_vertecies()
        visited = set()
        queue = deque([0])  # start from vertex 0

        while queue:
            vid = queue.popleft()

            # Skip if already visited
            if vid in visited:
                continue

            parents = g.predecessors(vid)

            current_cycles = [c for c in cycles if c[0] == vid]
            if current_cycles:  # vid is the first vertex in a cycle
                # Check if all non loop parents have been visited
                if all(p in visited for p in parents if not any(p in c for c in current_cycles)):
                    addr = g.vs[vid]["addr"]
                    yield addr
                    visited.add(vid)

                    # Enqueue children (successors)
                    for child in g.successors(vid):
                        if child not in visited:
                            queue.append(child)
                else:
                    for p in parents:
                        if p not in visited:
                            queue.append(p)
                    # Revisit this node later
                    queue.append(vid)

            # Check if all parents have been visited
            elif all(p in visited for p in parents):
                addr = g.vs[vid]["addr"]
                yield addr
                visited.add(vid)

                # Enqueue children (successors)
                for child in g.successors(vid):
                    if child not in visited:
                        queue.append(child)

            else:
                for p in parents:
                    if p not in visited:
                        queue.append(p)
                # Revisit this node later
                queue.append(vid)

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

    @lru_cache
    def _get_loop_vertecies(self) -> list[list[int]]:
        """
        Return loops as tuples of vertex indices,
        rotated so the vertex closest to 0 comes first in each loop.
        """

        g = self.graph

        def rotate_cycle(cycle):
            # Find index of vertex closest to 0
            distances = g.distances(0, cycle)[0]
            min_idx = distances.index(min(distances))

            return tuple(cycle[min_idx:] + cycle[:min_idx])

        return [rotate_cycle(cycle) for cycle in g.simple_cycles()]

    @lru_cache
    def get_loops(self) -> list[list[int]]:
        """
        Return loops as tuples of addresses, such that the first address in each list is the loop entry
        """
        return [[self.graph.vs[vid]["addr"] for vid in cycle] for cycle in self._get_loop_vertecies()]
