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

    def traverse_loopaware(self) -> Iterator[int]:
        """
        Traverse CFG in an order where each node is visited only after all
        non-loop parents are visited. Parents that are part of a loop back-edge
        to the node are ignored for this constraint.
        Yields addresses.
        """
        g = self.graph

        # strongly connected components
        scc = g.components(mode="STRONG")
        comp_index = scc.membership
        n_comp = len(scc)

        # condensation DAG
        dag = Graph(directed=True)
        dag.add_vertices(n_comp)
        for e in g.es:
            u, v = e.tuple
            cu, cv = comp_index[u], comp_index[v]
            if cu != cv:
                dag.add_edge(cu, cv)

        # topo order of SCCs
        comp_order = dag.topological_sorting(mode="OUT")

        visited = set()
        for comp in comp_order:
            nodes = scc[comp]

            if len(nodes) == 1:  # not a cycle
                v = nodes[0]
                if v not in visited:
                    yield self.graph.vs[v]["addr"]
                    visited.add(v)
            else:
                # cycle component
                # find candidate "entry points" = nodes with parent outside the SCC
                entry_candidates = []
                for v in nodes:
                    for p in g.predecessors(v):
                        if comp_index[p] != comp:
                            entry_candidates.append(v)
                            break

                # fallback if none found: just pick first node
                entry = entry_candidates[0] if entry_candidates else nodes[0]

                # yield entry first
                if entry not in visited:
                    yield self.graph.vs[entry]["addr"]
                    visited.add(entry)

                # then the rest in some order (input order here)
                for v in nodes:
                    if v not in visited:
                        yield self.graph.vs[v]["addr"]
                        visited.add(v)

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
