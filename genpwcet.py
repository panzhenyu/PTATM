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
                    "nrcallee": {}
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
    tracestr = '{"command": ["/home/pzy/project/PTATM/benchmark/benchmark"], "clock": "x86-tsc", "dump": {"main": {"main__0": {"normcost": {"time": [210538.0, 165132.0]}, "nrcallee": {"indirectCall": [1, 1], "fib": [1, 1], "directCall": [1, 1]}}, "main__1": {"normcost": {"time": [49174.0, 37884.0]}, "nrcallee": {"indirectJump": [2, 2], "fib": [1, 1], "indirectCall": [1, 1]}}, "fullcost": {"time": [504998.0, 392800.0]}}, "indirectCall": {"indirectCall__0": {"normcost": {"time": [53124.0, 41882.0]}, "nrcallee": {"foo": [2, 2]}}, "fullcost": {"time": [65072.0, 42436.0, 51674.0, 31884.0]}}, "foo": {"foo__0": {"normcost": {"time": [54384.0, 41676.0]}, "nrcallee": {}}, "fullcost": {"time": [36942.0, 17442.0, 28612.0, 13064.0]}}, "fib": {"fib__0": {"normcost": {"time": [85246.0, 64582.0]}, "nrcallee": {"fib": [2, 2]}}, "fullcost": {"time": [17618.0, 17044.0, 68174.0, 17072.0, 13476.0, 12808.0, 51640.0, 12942.0]}}, "directCall": {"directCall__0": {"normcost": {"time": [17466.0, 14398.0]}, "nrcallee": {}}, "fullcost": {"time": [17466.0, 14398.0]}}, "indirectJump": {"indirectJump__0": {"normcost": {"time": [35066.0, 27246.0]}, "nrcallee": {}}, "fullcost": {"time": [17850.0, 17216.0, 14304.0, 12942.0]}}}}'
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
    else:
        print("expression: ", linear_extd.expression())
        probs = [1e-1, 1e-2, 1e-3, 1e-4, 1e-5, 1e-6, 1e-7, 1e-8, 1e-9]
        pwcet = [linear_extd.isf(prob) for prob in probs]
        print("probs:", probs)
        print("pwcet:", pwcet)
