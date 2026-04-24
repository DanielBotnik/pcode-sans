from __future__ import annotations

from collections import deque
from collections.abc import Iterator
from typing import Optional

from igraph import Graph  # type: ignore[import-untyped]

# Minimum difference in node count between a single-back-edge loop and the
# merged (maximal) loop to consider it a distinct inner loop rather than a
# redundant outer-shell path.
INNER_LOOP_MIN_DIFF = 2


class CodeFlowGraph:
    def __init__(self) -> None:
        self.graph = Graph(directed=True)
        self.addr_to_vertex_id: dict[int, int] = dict()
        self._loop_vertices_cache: list[list[int]] | None = None
        self._loops_cache: list[list[int]] | None = None

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

    def get_parents(self, addr: int) -> list[int]:
        vertex_id = self.addr_to_vertex_id[addr]
        parent_vertex_ids = self.graph.predecessors(vertex_id)
        parent_addrs = [self.graph.vs[vid]["addr"] for vid in parent_vertex_ids]
        return parent_addrs

    def print_cfg(self) -> None:
        """Print the CFG vertices and edges, optionally plot it."""
        print(f"{len(self.graph.vs)} Vertices:")
        for v in self.graph.vs:
            addr = v["addr"] if "addr" in v.attributes() else v.index
            print(f"Vertex {v.index}: addr={hex(addr) if isinstance(addr, int) else addr}")

        print(f"\n{len(self.graph.es)} Edges:")
        for e in self.graph.es:
            src = self.graph.vs[e.source]["addr"] if "addr" in self.graph.vs[e.source].attributes() else e.source
            dst = self.graph.vs[e.target]["addr"] if "addr" in self.graph.vs[e.target].attributes() else e.target
            print(f"{hex(src) if isinstance(src, int) else src} -> {hex(dst) if isinstance(dst, int) else dst}")

    def traverse(self) -> Iterator[int]:
        """
        Traverse the graph starting from vertex 0.
        A node is yielded only when all its parents have been visited.
        If not all parents are visited, push the missing parents first.
        """
        g = self.graph
        loop_vertices = self._get_loop_vertices()
        cycles = self._group_cycles_by_header(loop_vertices)
        visited: set[int] = set()
        queue: deque[int] = deque([0])  # start from vertex 0

        while queue:
            vid = queue.popleft()

            if vid in visited:
                continue

            parents = g.predecessors(vid)

            if self._is_ready_to_visit(vid, parents, visited, cycles):
                addr = g.vs[vid]["addr"]
                yield addr
                visited.add(vid)

                for child in g.successors(vid):
                    if child not in visited:
                        queue.append(child)
            else:
                for p in parents:
                    if p not in visited:
                        queue.append(p)
                queue.append(vid)

    def _is_ready_to_visit(
        self,
        vid: int,
        parents: list[int],
        visited: set[int],
        cycles_by_header: dict[int, list[list[int]]],
    ) -> bool:
        """Check whether all required parents of vid have been visited."""
        current_cycles = cycles_by_header.get(vid, [])
        if current_cycles:
            # vid is a loop header: only require non-loop parents to be visited
            return all(p in visited for p in parents if not any(p in c for c in current_cycles))
        return all(p in visited for p in parents)

    @staticmethod
    def _group_cycles_by_header(loop_vertices: list[list[int]]) -> dict[int, list[list[int]]]:
        """Group loop vertex-lists by their first (header) vertex."""
        cycles_by_header: dict[int, list[list[int]]] = {}
        for cycle in loop_vertices:
            header = cycle[0]
            cycles_by_header.setdefault(header, []).append(list(cycle))
        return cycles_by_header

    def first_common_ancestor(self, addr1: int, addr2: int) -> Optional[int]:
        v1 = self.addr_to_vertex_id[addr1]
        v2 = self.addr_to_vertex_id[addr2]

        anc_u = set(self.graph.subcomponent(v1, mode="IN"))
        anc_v = set(self.graph.subcomponent(v2, mode="IN"))

        commons = anc_u & anc_v
        if not commons:
            return None

        # If one node can reach the other, prefer the ancestor node itself.
        # (If both can reach each other (same SCC), prefer the first argument.)
        if v1 in anc_v:
            return self.graph.vs[v1]["addr"]
        if v2 in anc_u:
            return self.graph.vs[v2]["addr"]

        # Otherwise pick the common ancestor that minimises the maximum distance to the two nodes.
        def score(a_idx: int) -> float:
            d1, d2 = self.graph.distances(a_idx, [v1, v2])[0]  # returns [dist_to_v1, dist_to_v2]
            return max(d1, d2)

        vertex_idx = min(commons, key=score)
        return self.graph.vs[vertex_idx]["addr"]

    def is_ancestor(self, addr1: int, addr2: int) -> bool:
        vertex1 = self.addr_to_vertex_id[addr1]
        vertex2 = self.addr_to_vertex_id[addr2]

        return vertex1 in self.graph.subcomponent(vertex2, mode="OUT")

    def _get_loop_vertices(self) -> list[list[int]]:
        """
        Return loops as tuples of vertex indices,
        rotated so the vertex closest to 0 comes first in each loop.
        """
        if self._loop_vertices_cache is not None:
            return self._loop_vertices_cache

        def rotate_cycle(cycle: list[int]) -> tuple[int, ...]:
            # Find index of vertex closest to 0
            distances = self.graph.distances(0, cycle)[0]
            min_idx = distances.index(min(distances))

            return tuple(cycle[min_idx:] + cycle[:min_idx])

        loops = self.find_natural_loops(self.graph, 0)
        self._loop_vertices_cache = [list(rotate_cycle(loop)) for loop in loops]
        return self._loop_vertices_cache

    def get_dominators(self, graph: Graph, entry_node: int = 0) -> dict[int, set[int]]:
        """
        Calculates the full set of dominators for every node.
        Uses igraph's native 'dominators()' which returns immediate dominators (idom).
        """

        idoms = graph.dominator(entry_node, mode="out")
        doms: dict[int, set[int]] = {}

        # Build full dominator sets from the immediate dominator chain
        # The root dominates itself
        doms[entry_node] = {entry_node}

        for node in range(graph.vcount()):
            if node in doms:
                continue

            curr = node
            chain: list[int] = []

            # Traverse up the dominator tree until we hit a known node (or root/-1)
            while curr not in doms:
                chain.append(curr)
                if curr >= len(idoms):  # Safety
                    doms[curr] = {curr}
                    break
                idom = idoms[curr]
                if idom < 0 or idom == curr:  # Root or unreachable
                    doms[curr] = {curr}
                    break
                curr = idom

            # Reconstruct sets: Dom(u) = {u} U Dom(idom(u))
            known_doms = doms[curr]
            while chain:
                child = chain.pop()
                child_doms = known_doms.copy()
                child_doms.add(child)
                doms[child] = child_doms
                known_doms = child_doms

        return doms

    # --- Natural Loop Finder ---

    def find_natural_loops(self, graph: Graph, entry_node: int = 0) -> list[list[int]]:
        """
        Finds natural loops in the graph.

        Strategy:
        1. Identify back-edges (u -> v where v dominates u).
        2. Group back-edges by header.
        3. For each header:
           a. Generate the 'Merged' loop (Union of all back-edges).
              This represents the full loop structure (Outer Loop).
           b. Generate individual loops for each back-edge.
              This captures distinct Inner Loops.
        4. Filter:
           - If an individual loop is a subset of the Merged loop (same header)
             AND it is 'nearly identical' (e.g., only missing 1 node),
             we assume it is just the 'Outer Shell' and discard it.
           - We keep individual loops that are significantly different (Inner Loops).
        """
        dominators = self.get_dominators(graph, entry_node)

        # Step A: Identify all back-edges and group by header
        back_edges_by_header: dict[int, list[int]] = {}
        for edge in graph.es:
            u, v = edge.tuple  # u -> v
            # Check if v dominates u (definition of a back-edge)
            if v in dominators[u]:
                back_edges_by_header.setdefault(v, []).append(u)

        found_loops: list[list[int]] = []

        # Helper to construct a loop body from a list of tails for a specific header
        def construct_loop(header: int, tails: list[int]) -> set[int]:
            loop_body: set[int] = {header}
            stack = list(tails)
            # Add tails initially
            for t in tails:
                loop_body.add(t)

            while stack:
                current = stack.pop()
                for pred in graph.predecessors(current):
                    # Add predecessor if it's dominated by the header
                    # and not yet in the body
                    if pred not in loop_body and header in dominators[pred]:
                        loop_body.add(pred)
                        stack.append(pred)
            return loop_body

        # Step B: Generate loops for each header
        for header, tails in back_edges_by_header.items():

            # 1. Always generate and keep the Merged Loop (The Maximal Loop)
            merged_loop_body = construct_loop(header, tails)
            found_loops.append(sorted(list(merged_loop_body)))

            # If there's only one back-edge, we are done for this header
            if len(tails) <= 1:
                continue

            # 2. Check individual back-edges for Nested Inner Loops
            for tail in tails:
                single_loop_body = construct_loop(header, [tail])

                # --- FILTERING LOGIC ---
                # Compare Single Loop vs Merged Loop
                # We only keep the Single Loop if it represents a DISTINCT sub-structure.
                # If the Single Loop is "almost" the Merged Loop (e.g. diff <= 1 node),
                # it is likely just the Outer Loop's main path, which is redundant.

                diff_size = len(merged_loop_body) - len(single_loop_body)

                if diff_size >= INNER_LOOP_MIN_DIFF:
                    found_loops.append(sorted(list(single_loop_body)))

        # Step C: Global Deduplication
        unique_loops: list[list[int]] = []
        seen: set[tuple[int, ...]] = set()
        for loop in found_loops:
            t_loop = tuple(loop)
            if t_loop not in seen:
                seen.add(t_loop)
                unique_loops.append(loop)

        return unique_loops

    def get_loops(self) -> list[list[int]]:
        """
        Return loops as tuples of addresses, such that the first address in each list is the loop entry
        """
        if self._loops_cache is not None:
            return self._loops_cache

        self._loops_cache = [
            [self.graph.vs[vid]["addr"] for vid in cycle] for cycle in self._get_loop_vertices()
        ]
        return self._loops_cache
