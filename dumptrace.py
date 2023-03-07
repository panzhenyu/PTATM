
import argparse, sys
from TraceTool import *

"""
Usage: python3 dumptrace.py command [options] file [file]
Dump segment info from (raw/json)trace file.

[command]
    parse           parse raw traces into one json trace.
    merge           merge json traces into one json trace.
    graph           generate calling graph for a json trace.

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

    then we output json trace:
        {
            "command": ["command"]
            "clock": "clock"
            "dump": {
                "main": {
                    // probe: time list
                    "main__0": {
                        "normcost": [1], (main__1 - main__0)
                        "nrcallee": {}
                    }, 
                    "main__1": {
                        "normcost": [2], (func__0 - main__1 + main__2 - func__return)
                        "nrcallee": { "func": [1] }
                    }, 
                    "main__2": {
                        "normcost": [1], (main__return - main__2)
                        "nrcallee": {}
                    },
                    "fullcost": [8], (main__return - main__0)

                }, // Time detail of one function.
                "func": {
                    "func__0": {
                        "normcost": [2], (foo__0 - func__0 + func__1 - foo__return)
                        "nrcallee": { "foo": [1] }
                    }, 
                    "func__1": {
                        "normcost": [1], (func__return - func__1)
                        "nrcallee": {}
                    }, 
                    "funcost": [4], (func__return - func__0)
                },
                "foo": {
                    "foo__0": {
                        "normcost": [1] (foo__return - foo__0)
                        "nrcallee": {}
                    }, 
                    "funcost": [1], (foo__return - foo__0)
                }
            } // Dump timing information for all functions.
        } // Basic information of this dump.
    Note that every non-exit func should always appear in nrcallee and dump concurrently.
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
        [/home/pzy/project/PTATM/benchmark/benchmark] [x86-tsc]
        1631827067753170,main__0
        1631827067896650,indirectCall__0
        1631827067912938,foo__0
        1631827067941550,foo__return
        1631827067948324,indirectCall__return
        1631827067955374,fib__0
        1631827067969146,fib__0
        1631827067982622,fib__return
        1631827067988526,fib__0
        1631827068001334,fib__return
        1631827068007014,fib__return
        1631827068014598,directCall__0
        1631827068028996,directCall__return
        1631827068036014,main__1
        1631827068049158,indirectJump__0
        1631827068063462,indirectJump__return
        1631827068069810,indirectJump__0
        1631827068082752,indirectJump__return
        1631827068088628,fib__0
        1631827068101570,fib__return
        1631827068107656,indirectCall__0
        1631827068120768,foo__0
        1631827068133832,foo__return
        1631827068139540,indirectCall__return
        1631827068145970,main__return
    """

    traceObj = RawTraceBuilder().buildFrom(rawTrace)
    if traceObj is None:
        sys.stderr.write("Build raw trace failed.\n")
    else:
        print(JsonTraceSerializer().serialize(traceObj))
