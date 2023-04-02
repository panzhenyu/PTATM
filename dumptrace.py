
import argparse, sys
from SegmentInfoCollector.TraceTool import *

"""
Usage: python3 dumptrace.py command [options] file [file]
Dump segment info from (raw/json)trace file.

[command]
    parse       parse raw traces into one json trace.
    merge       merge json traces into one json trace.
    strip       strip field for json trace.

[options]
    -o, --output    output file, default is stdout.

[input format]
    See output of gentrace.py.

[output format]
    if raw trace has content:
        [command] [clock]
            1,main__0
            2,main__1
            3,func__0
            4,foo__0
            5,foo__return
            6,func__1
            7,func__return
            8,main__2
            9,main__return

    then we output time trace(note that every non-exit func should always appear in nrcallee and dump concurrently):
        {
            "command": ["command"]
            "clock": "clock",
            "dump": {
                "main": {
                    // probe: time list
                    "main__0": {
                        "normcost": {
                            "time": [1] (main__1 - main__0)
                        }, 
                        "nrcallee": []
                    }, 
                    "main__1": {
                        "normcost": {
                            "time": [2] (func__0 - main__1 + main__2 - func__return)
                        }, 
                        "nrcallee": [["func"]]
                    }, 
                    "main__2": {
                        "normcost": {
                            "time": [1] (main__return - main__2)
                        }, 
                        "nrcallee": []
                    },
                    "fullcost": {
                        "time": [8], (main__return - main__0)
                    }
                }, // Time detail of one function.
                "func": {
                    "func__0": {
                        "normcost": {
                            "time": [2] (foo__0 - func__0 + func__1 - foo__return)
                        },
                        "nrcallee": [["foo"]]
                    }, 
                    "func__1": {
                        "normcost": {
                            "time": [1] (func__return - func__1)
                        }, 
                        "nrcallee": []
                    }, 
                    "funcost": {
                        "time": [4] (func__return - func__0)
                    }
                },
                "foo": {
                    "foo__0": {
                        "normcost":  {
                            "time": [1] (foo__return - foo__0)
                        }
                        "nrcallee": []
                    }, 
                    "funcost":  {
                        "time": [1] (foo__return - foo__0)
                    }
                }
            } // Dump timing information for all functions.
        } // Basic information of this dump.

    whose calling graph may be like this:
        main -> func -> foo
"""

if __name__ == "__main__":
    mode = "parse"
    files = []
    output = None

    if mode == "parse":
        pass
    elif mode == "merge":
        pass
    elif mode == "graph":
        pass
    else:
        sys.stderr.write("unrecognized mode %s\n" % mode)
        exit(-1)

    rawTrace =  """
        [/home/pzy/project/PTATM/benchmark/benchmark] [x86-tsc]
        1631826845627326,main__0
        1631826845810806,indirectCall__0
        1631826845830378,foo__0
        1631826845867320,foo__return
        1631826845875878,indirectCall__return
        1631826845884884,fib__0
        1631826845902912,fib__0
        1631826845920530,fib__return
        1631826845928416,fib__0
        1631826845945460,fib__return
        1631826845953058,fib__return
        1631826845962256,directCall__0
        1631826845979722,directCall__return
        1631826845988576,main__1
        1631826846005320,indirectJump__0
        1631826846023170,indirectJump__return
        1631826846031658,indirectJump__0
        1631826846048874,indirectJump__return
        1631826846056758,fib__0
        1631826846073830,fib__return
        1631826846082004,indirectCall__0
        1631826846099402,foo__0
        1631826846116844,foo__return
        1631826846124440,indirectCall__return
        1631826846132324,main__return
    """

    rawTrace =  """
        [/home/pzy/project/PTATM/benchmark/benchmark] [x86-tsc]
        1,main__0
        2,main__1
        3,foo__0
        4,foo__return
        5,recursive__0
        6,recursive__1
        7,foo__0
        8,foo__return
        9,recursive__0
        10,recursive__1
        11,func__0
        12,func__return
        13,recursive__return
        14,recursive__return
        15,main__2
        16,main__2
        17,main__return
    """

    traceObj = Trace()
    filler = RawTraceStringFiller(traceObj)
    if filler.fill(rawTrace) == False:
        sys.stderr.write("Build raw trace failed.\n%s" % filler.err_msg)
    else:
        print(JsonTraceSerializer(4).serialize(traceObj))
        print(filler.err_msg)
        # CostTimeStripper(traceObj).strip()
        # print(JsonTraceSerializer(4).serialize(traceObj))
        # CalleeStripper(traceObj).strip()
        # print(JsonTraceSerializer(4).serialize(traceObj))
