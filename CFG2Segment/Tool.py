import numpy

# Provides helper functions for graph operation.
class GraphTool:
    # Traversal whole graph begin with start node, return all node found.
    # [in]  start           Start point of the whole traversal.
    # [in]  getNeighbor     A function object provides a node list of current node which will be traveled in next iteration.
    # [in]  ignoreNeighbor  A function object tells us whether travel a node or not.
    # [out]                 A traveled node list.
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
