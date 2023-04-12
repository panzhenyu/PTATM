
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

    then we output time trace(note that every non-exit func should always appear in callinfo and dump concurrently):
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
                        "callinfo": []
                    }, 
                    "main__1": {
                        "normcost": {
                            "time": [2] (func__0 - main__1 + main__2 - func__return)
                        }, 
                        "callinfo": [["func"]]
                    }, 
                    "main__2": {
                        "normcost": {
                            "time": [1] (main__return - main__2)
                        }, 
                        "callinfo": []
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
                        "callinfo": [["foo"]]
                    }, 
                    "func__1": {
                        "normcost": {
                            "time": [1] (func__return - func__1)
                        }, 
                        "callinfo": []
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
                        "callinfo": []
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
        6329108218566684,main__0
        6329108218778830,indirectCall__0
        6329108218800638,foo__0
        6329108218841606,foo__return
        6329108218850940,indirectCall__return
        6329108218860826,fib__0
        6329108218880910,fib__0
        6329108218900720,fib__return
        6329108218909540,fib__0
        6329108218928630,fib__return
        6329108218937104,fib__return
        6329108218946876,directCall__0
        6329108218967186,directCall__return
        6329108218977098,main__1
        6329108218996656,indirectJump__0
        6329108219016572,indirectJump__return
        6329108219026176,indirectJump__0
        6329108219045506,indirectJump__return
        6329108219054344,fib__0
        6329108219073546,fib__return
        6329108219082684,indirectCall__0
        6329108219102290,foo__0
        6329108219121818,foo__return
        6329108219130310,indirectCall__return
        6329108219139604,main__return
        [/home/pzy/project/PTATM/benchmark/benchmark] [x86-tsc]
        6329108476983538,main__0
        6329108477195860,indirectCall__0
        6329108477218248,foo__0
        6329108477259682,foo__return
        6329108477269836,indirectCall__return
        6329108477280078,fib__0
        6329108477300282,fib__0
        6329108477319900,fib__return
        6329108477328714,fib__0
        6329108477347828,fib__return
        6329108477356208,fib__return
        6329108477366358,directCall__0
        6329108477386622,directCall__return
        6329108477396464,main__1
        6329108477416248,indirectJump__0
        6329108477437090,indirectJump__return
        6329108477446594,indirectJump__0
        6329108477465880,indirectJump__return
        6329108477474800,fib__0
        6329108477493956,fib__return
        6329108477503072,indirectCall__0
        6329108477522558,foo__0
        6329108477542018,foo__return
        6329108477550498,indirectCall__return
        6329108477559886,main__return
    """

    # rawTrace =  """
    #     [/home/pzy/project/PTATM/benchmark/benchmark] [x86-tsc]
    #     1,main__0
    #     2,main__1
    #     3,foo__0
    #     4,foo__return
    #     5,recursive__0
    #     6,recursive__1
    #     7,foo__0
    #     8,foo__return
    #     9,recursive__0
    #     10,recursive__1
    #     11,func__0
    #     12,func__return
    #     13,recursive__return
    #     14,recursive__return
    #     15,main__2
    #     16,main__2
    #     17,main__return
    # """

    traceObj = Trace()
    filler = RawTraceStringFiller(traceObj)
    if filler.fill(rawTrace) == False:
        sys.stderr.write("Build raw trace failed.\n%s" % filler.err_msg)
    else:
        print(filler.err_msg)
        # CostTimeStripper(traceObj).strip()
        # print(JsonTraceSerializer(4).serialize(traceObj))
        CallinfoStripper(traceObj).strip()
        print(JsonTraceSerializer().serialize(traceObj))
