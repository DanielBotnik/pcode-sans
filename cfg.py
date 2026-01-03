from collections import deque
from functools import lru_cache
from igraph import Graph  # type: ignore[import-untyped]

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

    def first_common_ancestor(self, addr1: int, addr2: int) -> int | None:
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

    @lru_cache
    def _get_loop_vertecies(self) -> list[list[int]]:
        """
        Return loops as tuples of vertex indices,
        rotated so the vertex closest to 0 comes first in each loop.
        """

        def rotate_cycle(cycle):
            # Find index of vertex closest to 0
            distances = self.graph.distances(0, cycle)[0]
            min_idx = distances.index(min(distances))

            return tuple(cycle[min_idx:] + cycle[:min_idx])

        loops = self.find_natural_loops(self.graph, 0)
        return [rotate_cycle(loop) for loop in loops]

    def get_dominators(self, graph, entry_node=0):
        """
        Calculates the full set of dominators for every node.
        Uses igraph's native 'dominators()' which returns immediate dominators (idom).
        """

        idoms = graph.dominator(entry_node, mode="out")
        doms = {}

        # Build full dominator sets from the immediate dominator chain
        # The root dominates itself
        doms[entry_node] = {entry_node}

        for node in range(graph.vcount()):
            if node in doms:
                continue

            curr = node
            chain = []

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

    # --- 2. Natural Loop Finder ---

    def find_natural_loops(self, graph, entry_node=0):
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
        back_edges_by_header = {}
        for edge in graph.es:
            u, v = edge.tuple  # u -> v
            # Check if v dominates u (definition of a back-edge)
            if v in dominators[u]:
                if v not in back_edges_by_header:
                    back_edges_by_header[v] = []
                back_edges_by_header[v].append(u)

        found_loops = []

        # Helper to construct a loop body from a list of tails for a specific header
        def construct_loop(header, tails):
            loop_body = {header}
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

                # Heuristic: If difference is small (<=1 node), discard.
                # If difference is large (>1), it implies there is a significant
                # 'other' part of the loop (the inner loop) that this path excludes.
                if diff_size > 1:
                    found_loops.append(sorted(list(single_loop_body)))

        # Step C: Global Deduplication
        # (Just in case different headers produced identical sets, though rare in Natural Loops)
        unique_loops = []
        seen = set()
        for loop in found_loops:
            t_loop = tuple(loop)
            if t_loop not in seen:
                seen.add(t_loop)
                unique_loops.append(loop)

        return unique_loops

    @lru_cache
    def get_loops(self) -> list[list[int]]:
        """
        Return loops as tuples of addresses, such that the first address in each list is the loop entry
        """
        return [[self.graph.vs[vid]["addr"] for vid in cycle] for cycle in self._get_loop_vertecies()]
