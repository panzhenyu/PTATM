import argparse, angr
from sys import stdout
from CFG2Segment.CFGBase import CFG
from CFG2Segment.CFGRefactor import FunctionalCFGRefactor
from CFG2Segment.SFGBase import SFG
from CFG2Segment.SFGBuilder import FunctionalSFGBuilder
from CFG2Segment.Tool import GraphTool

"""
python3 dumpseg.py [options] binary
    -o, --output    output file for segment info, default is stdout.
    -f, --func      function interests that separated by ',' and ordered by priority, default is main only.
    -s, --max-seg   max segment num, default is 2.

[output format]
    [First line]    Topological list of functions.
    [Rest lines]    Each line is a segment profile(segment name, corresponding probe)
"""

if __name__ == "__main__":
    binary = "/home/pzy/project/PTATM/benchmark/benchmark"
    output = stdout
    functions = ["main"]
    max_seg = 2

    # Parse binary with angr.
    angr_project = angr.Project(binary, load_options={'auto_load_libs': False})
    angr_cfg = angr_project.analyses.CFGFast()

    # Refactor CFG.
    cfg = CFG.fromAngrCFG(angr_cfg)
    cfg_refactor = FunctionalCFGRefactor()
    refactor_result = cfg_refactor.refactor(cfg)

    # Build SFG.
    sfg = SFG(cfg)
    sfg_builder = FunctionalSFGBuilder(max_seg, functions)
    build_result = sfg_builder.build(sfg)

    # Gen topological list for functions.
    graph = dict()
    for name in functions:
        # Some callee may not exist cause plt fuction or other reasons, so do those in functions.
        print([hex(x) for x in cfg.getFunc(name).callees])
    # topoList = GraphTool.topologicalSort(graph, functions)

    # Output topological list and segment info.
    output.write("OK")
