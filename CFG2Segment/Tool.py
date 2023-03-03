from abc import abstractmethod
import numpy

# Provides helper functions for graph operation.
class GraphTool:
    # Traversal the whole graph begin with start node, return all node found.
    # [in]  start           Start point of the whole traversal.
    # [in]  getNeighbor     A function object provides a node list of current node which will be traveled in next iteration.
    # [in]  ignoreNeighbor  A function object tells us whether travel a node or not.
    # [out]                 A traveled node list.
    @staticmethod
    def traversal(start, getNeighbor, ignoreNeighbor) -> set:
        visit, stack = set([start]), [start]
        while len(stack) > 0:
            cur = stack.pop()
            for node in getNeighbor(cur):
                if node in visit or ignoreNeighbor(node):
                    continue
                visit.add(node)
                stack.append(node)
        return visit

    # Do topological sort for a graph.
    # [in]  graph   Input graph for topological sort, it is a dict mapping node to his neighbor list.
    # [in]  prio    A list contains node priorites used to break circle, the smaller index, the higher priority.
    # [out]         A vertex list in topological order, whose vertexs are only come from prio.
    @staticmethod
    def topologicalSort(graph: dict[any: list | set], prio: list) -> list:
        vertexs, nr_vertex, vindex, topolist = prio, len(prio), dict(), list()
        adjmat = numpy.zeros((nr_vertex, nr_vertex), dtype=int)
        # Init vindex.
        for idx, v in enumerate(vertexs):
            vindex[v] = idx
        # Init adjmat.
        for v in vertexs:
            for neighbor in [node for node in graph[v] if node in prio]:
                # That means v relys on neighbor.
                adjmat[vindex[v]][vindex[neighbor]] = 1
        # Remove circle.
        for i in range(nr_vertex):
            for j in range(i, nr_vertex):
                # Here we meet with a circle.
                if adjmat[i][j] == 1 and adjmat[i][j] == adjmat[j][i]:
                    if i <= j:
                        # Break the circle with priority.
                        adjmat[j][i] = 0
        # Start topological sorting.
        restidx = list(range(nr_vertex))
        while len(topolist) < nr_vertex:
            for i in restidx:
                # When current vertex doesn't have dependent vecters.
                if sum(adjmat[i]) == 0:
                    # Remove this index.
                    restidx.remove(i)
                    # Add it to topolist.
                    topolist.append(vertexs[i])
                    # Dependency i has been resolved, remove it for other vertexs.
                    for k in restidx:
                        adjmat[k][i] = 0
        return topolist

class SegmentSearcher:
    # Traversal the whole graph begin with start node, return all node found.
    # [in]  start           Start point of the whole traversal.
    # [in]  ends            A function object provides a node list of current node which will be traveled in next iteration.
    # [in]  getSuccessors   A function object tells us whether travel a node or not.
    # [out]                 A set contains separators.
    @abstractmethod
    def search(self, start, ends: set, getSuccessors) -> set:
        pass

class PathCoverSearcher(SegmentSearcher):
    def search(self, start, ends: set, getSuccessors) -> set:
        # 1. Search path in DFS manner.
        #   1.1 When we met with circle, that means all nodes within this circle aren't candidate, we should remove these nodes from path.
        #   1.2 If path ends with expected node(eq to end or return node), save the rest nodes.
        # 2. The common nodes of all path are what we want.

        # DFS stack: (vertex, depth)
        bs, path = [(start, 0)], list()
        # candidates: {vertex: num}
        pathNum, candidates, circleNode = 0, dict(), set()
        while len(bs) > 0:
            cur, depth = bs.pop()
            # Update path, here cur won't cause a circle.
            if depth < len(path):
                path = path[0:depth]
            path.append(cur)
            pathSet = set(path)
            # Update bs for DFS.
            for successor in getSuccessors(cur):
                # We met with a circle(successor-> ... -> cur).
                if successor in pathSet:
                    for node in path[path.index(successor):]:
                        circleNode.add(node)
                # The path terminated when we met with endpoint.
                elif successor in ends:
                    # Skip the entryNode.
                    for node in [validNode for validNode in path[1:] if validNode not in circleNode]:
                        candidates.setdefault(node, 0)
                        candidates[node] += 1
                    pathNum += 1
                else:
                    bs.append((successor, depth+1))
        # Output vertex when candidates[vertex] == pathNum.
        return [vertex for vertex, num in candidates.items() if num == pathNum]

class BlockCheckSearcher(SegmentSearcher):
    def search(self, start, ends: set, getSuccessors) -> set:
        # 1. Find a path start with entry block and end with the node saticfies isEndpoint.
        # 2. Check each path node and collect those satisfy isSeperatorNode.

        # Search a valid path.
        path = self.searchValidPath(start, ends, getSuccessors)
        # Collect all separate nodes.
        return [vertex for vertex in path if self.isSeparateNode(vertex, start, ends, getSuccessors)]

    def searchValidPath(self, start, ends: set, getSuccessors):
        # DFS stack: (vertex, depth)
        bs, path = [(start, 0)], list()
        while len(bs) > 0:
            cur, depth = bs.pop()
            # Update path, here curNode won't cause a circle.
            if depth < len(path):
                path = path[0:depth]
            path.append(cur)
            pathSet = set(path)
            # Update bs for DFS.
            for successor in getSuccessors(cur):
                if successor in pathSet:
                    continue
                elif successor in ends:
                    return path[1:]
                else:
                    bs.append((successor, depth+1))
        return list()

    def isSeparateNode(self, target, start, ends: set, getSuccessors):
        if target == start:
            return False
        # Get target set and entry set.
        targetSet = GraphTool.traversal(target, getSuccessors, lambda _: False)
        startSet = GraphTool.traversal(start, getSuccessors, lambda x: x == target)
        # Return valid targetNode.
        # return 0 != len(targetSet&endPoints) and 0 == len(targetSet&entrySet-endPoints)
        return 0 != len(targetSet&ends) and 0 == len(startSet&ends) and 0 == len(targetSet&startSet)
