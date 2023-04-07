import argparse, json
import numpy as np
import matplotlib.pyplot as plt
from SegmentInfoCollector import TraceTool
from PWCETGenerator import EVTTool, PWCETSolver

"""
Usage: python3 genpwcet.py command [options] trace
Generate pwcet estimate/curve for target functions. This tools will set 
symbolic timing analysis field(such as gumbel, pareto) into trace file.

[command]
    image           generate pwcet curve for each function.
    value           generate pwcet estimate for each function.

[options]
    -f, --func      Target functions to generate pwcet, splited by ',' and default is main.
    -t, --type      Choost type of EVT family(GEV or GPD), default is GPD.
    -r, --rebuild   Force to rebuild symbolic field from time field even if it's already exist.
    -s, --precision Set precision for output, default is 4.
    -o, --output    Output file to save result, default value: ${file}_pwcet.png for image mode and stdout for value mode.
    -p, --prob      Exceedance probability, ignored in image mode, default is 1e-6.

    We generate symbolic trace with EVT tools like this:
    {
        "command": ["command"], 
        "clock": "clock", 
        "dump": {
            "main": {
                "main__0": {
                    "normcost": {
                        "time": [1], (main__1 - main__0)
                        "pareto": dict of pareto args, 
                        ...
                    }, 
                    "callinfo": []
                },
                ...
                "fullcost": {
                    "time": [8], (main__return - main__0),
                    "pareto": dict of pareto args, 
                    ...
                }
            }, 
            ...
        }
    }
"""

# Plot sf, where sf = 1 - cdf.
def plot_isf(isf):
    y = np.linspace(0, 1, 1000)
    x = [isf(prob) for prob in y]

    fig, ax = plt.subplots(1, 1)
    ax.plot(x, y, 'k-', lw=5, alpha=0.6, label='isf')

if __name__ == "__main__":
    # Build trace object.
    tracestr = '{"command": ["/home/pzy/project/PTATM/benchmark/benchmark"], "clock": "x86-tsc", "dump": {"foo": {"fullcost": {"time": [1.0, 1.0]}, "foo__0": {"normcost": {"time": [1.0, 1.0]}, "callinfo": []}}, "func": {"fullcost": {"time": [1.0]}, "func__0": {"normcost": {"time": [1.0]}, "callinfo": []}}, "recursive": {"fullcost": {"time": [4.0, 9.0]}, "recursive__0": {"normcost": {"time": [2.0]}, "callinfo": []}, "recursive__1": {"normcost": {"time": [5.0]}, "callinfo": [["foo", "recursive", "func"]]}}, "main": {"fullcost": {"time": [16.0]}, "main__0": {"normcost": {"time": [1.0]}, "callinfo": []}, "main__1": {"normcost": {"time": [3.0]}, "callinfo": [["foo", "recursive"]]}, "main__2": {"normcost": {"time": [2.0]}, "callinfo": []}}}}'
    traceObj = TraceTool.Trace()
    TraceTool.JsonTraceFiller(traceObj).fill(tracestr)
    print(TraceTool.JsonTraceSerializer(2).serialize(traceObj))

    # Solve trace object with ExponentialParetoSegmentListSolver.
    solver = PWCETSolver.ExponentialParetoSegmentListSolver()
    solver.genSymbolicTrace(traceObj)
    print(TraceTool.JsonTraceSerializer(2).serialize(traceObj))

    linear_extd = solver.solve(traceObj, "main")
    if linear_extd is None:
        print("solve failed")
        print(solver.err_msg)
    else:
        print("expression: ", linear_extd.expression())
        probs = [1e-1, 1e-2, 1e-3, 1e-4, 1e-5, 1e-6, 1e-7, 1e-8, 1e-9]
        pwcet = [linear_extd.isf(prob) for prob in probs]
        print("probs:", probs)
        print("pwcet:", pwcet)
