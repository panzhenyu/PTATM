import argparse, angr
from functools import reduce
from CFG2Segment.CFGBase import CFG
from CFG2Segment.CFGRefactor import FunctionalCFGRefactor
from CFG2Segment.SFGBase import SFG
from CFG2Segment.SFGBuilder import FunctionalSFGBuilder

"""
Usage: python3 genprobe.py [options] binary
Generate segment probe for interested functions of binary file.

    -f, --func      interested functions(separated by ',' or provide multiple option), default is main only.
    -s, --max-seg   max segment num, default is 2.

[output format]
    probes separate by ','.
"""

if __name__ == "__main__":
    binary = "/home/pzy/project/PTATM/benchmark/benchmark"
    functions = list(set(["main", "indirectCall", "foo", "fib", "indirectJump", "directCall"]))
    max_seg = 2

    # Parse binary with angr.
    angr_project = angr.Project(binary, load_options={'auto_load_libs': False})
    angr_cfg = angr_project.analyses.CFGFast()

    # Refactor CFG.
    cfg = CFG(angr_cfg)
    cfg_refactor = FunctionalCFGRefactor()
    refactor_result = cfg_refactor.refactor(cfg)

    # Build SFG.
    sfg = SFG(cfg)
    sfg_builder = FunctionalSFGBuilder(max_seg, functions)
    build_result = sfg_builder.build(sfg)

    # Remove function who doesn't exist in SFG.
    for name in functions:
        # TODO: Later if we can create probe with address, we can remove default name restriction.
        cur = sfg.getSegmentFunc(name)
        if None == cur or cur.function.is_default_name:
            # TODO: Add a warning?
            functions.remove(name)

    # Collect calling graph and topological list for functions.
    # This step may remove some function from original function list(functions), cause some function may not exist or has a default name.
    # graph = dict()
    # for name in functions:
        # Some callee may not exist cause plt fuction or other reasons, so do those in functions.
        # cur = sfg.getSegmentFunc(name)
        # Function doesn't exist or have a default name.
        # if None == cur or cur.function.is_default_name:
        #     functions.remove(name)
        #     continue
        # callees = [sfg.getSegmentFuncByAddr(addr) for addr in cur.function.callees]
        # graph[name] = [callee.function.name for callee in callees if callee is not None]
    # topoList = GraphTool.topologicalSort(graph, functions)

    # Collect probes from segment information.
    # Probe format: EVENT=PROBE => segment.name=function.name+offset
    probes = []
    for name in functions:
        segfunc = sfg.getSegmentFunc(name)
        for segment in segfunc.segments:
            offset = hex(segment.startpoint.addr - segfunc.addr)
            probe_prefix = segment.name + "="
            probe_suffix = segfunc.name + ("+" + offset if offset != "0x0" else '')
            probes.append(probe_prefix + probe_suffix)
        probes.append(segfunc.name + "=" + segfunc.name + r"%return")

    # Output
    print(reduce(lambda x, y: x + ',' + y, probes))
