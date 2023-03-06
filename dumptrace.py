from abc import abstractmethod
import argparse, json, re, sys
from inspect import trace
from textwrap import indent

from numpy import append
from CFG2Segment.SFGBase import SegmentFunction

"""
Usage: python3 dumptrace.py command [options] file [file]
[command]
    parse           parse raw traces into one json trace.
    merge           merge json traces into one json trace.
    graph           generate calling graph for a json trace.
[options]
    -o, --output    output file, default is stdout.

Dump segment info from (raw/json)trace file.

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

class Trace:
    # Global constants.
    KEY_COMMAND     = "command"
    KEY_CLOCK       = "clock"
    KEY_DUMP        = "dump"
    KEY_NORMCOST    = "normcost"
    KEY_NRCALLEE    = "nrcallee"
    KEY_FULLCOST    = "fullcost"
    # Segment related constants.
    SEGNO_RETURN    = "return"

    def __init__(self) -> None:
        self.command = set()
        self.clock = None
        self.dump = dict()

    # Modifer.
    def mergeFuncDump(self, fname: str, fdump: dict):
        if fname in self.dump:
            cur = self.dump[fname]
            for key, value in fdump.items():
                if key == Trace.KEY_FULLCOST:
                    # Merge full function execution time.
                    cur.setdefault(key, list()).extend(value)
                elif key not in cur:
                    # Add a new segment.
                    cur[key] = value.copy()
                else:
                    # Merge segment.
                    cur[key].setdefault(Trace.KEY_NORMCOST, list()).extend(value[Trace.KEY_NORMCOST])
                    cur_nrcallee = cur[key].setdefault(Trace.KEY_NRCALLEE, dict())
                    # Merge nrcallee for segment.
                    for calleeName, nrcalleeList in value[Trace.KEY_NRCALLEE].items():
                        cur_nrcallee.setdefault(calleeName, list()).extend(nrcalleeList)
        else:
            self.dump[fname] = fdump.copy()

    def mergeTrace(self, rhs) -> bool:
        if self.clock != rhs.clock:
            return False
        self.command |= rhs.command
        for fname, fdump in rhs.dump.items():
            self.mergeFuncDump(fname, fdump)
        return True

    # Utils
    def genCallingGraph(self) -> dict[str:list[str]|set[str]]:
        graph = dict()
        for fname, fdump in self.dump.items():
            graph[fname] = set()
            for key, value in fdump.items():
                if key != Trace.KEY_FULLCOST:
                    graph[fname] |= set(value[Trace.KEY_NRCALLEE].keys())
        return graph

class TraceBuilder:
    @abstractmethod
    def buildFrom(self, target) -> Trace|None:
        pass

class JsonTraceBuilder(TraceBuilder):
    def buildFrom(self, target: str) -> Trace|None:
        jsonobj = json.loads(target)
        if Trace.KEY_COMMAND not in jsonobj or Trace.KEY_CLOCK not in jsonobj or Trace.KEY_DUMP not in jsonobj:
            sys.stderr.write("Json trace format error.\n")
            return None
        trace = Trace()
        trace.command = set(jsonobj[Trace.KEY_COMMAND])
        trace.clock = jsonobj[Trace.KEY_CLOCK]
        trace.dump = jsonobj[Trace.KEY_DUMP].copy()
        # TODO: Maybe we should check format for trace.dump?
        return trace

class TimeTraceBuilder(TraceBuilder):
    def __init__(self, command: str, clock: str) -> None:
        self.command = command
        self.clock = clock

    # Each item in timetraces is a time trace such as '1,main__0'.
    def buildFrom(self, target: list[str]) -> Trace | None:
        # Init trace object.
        traceObject = Trace()
        traceObject.command.add(self.command)
        traceObject.clock = self.clock
        # Segment stack contains items whose format is (time, funcname, segno, and callstack contains items of func entry and func return, 
        # whose format is as same as segment stack.
        segstack, callstack = list(), list()
        try:
            timetraces = [trace.split(',') for trace in target]
            for time, segname in timetraces:
                funcname, segno = SegmentFunction.parseSegmentName(segname)
                # print(time, segname, funcname, segno, SegmentFunction.entrySegment(segno), segno == Trace.SEGNO_RETURN)
                # print(segstack)
                # print(callstack)
                last_time, last_funcname, last_segno = segstack[-1] if len(segstack) != 0 else (None, None, None)
                last_segname = SegmentFunction.makeSegmentName(last_funcname, last_segno) if last_funcname != None else None

                # A piece of last segment has been executed, add time cost to it.
                if last_segname != None:
                    traceObject.dump.setdefault(last_funcname, dict()).setdefault(last_segname, dict())     \
                        .setdefault(Trace.KEY_NORMCOST, [0])[0] += float(time) - float(last_time)

                if SegmentFunction.entrySegment(segno):
                    # Entry segment meas a function call.
                    segstack.append([time, funcname, segno])
                    callstack.append((time, funcname))
                    if last_segname != None:
                        traceObject.dump.setdefault(last_funcname, dict()).setdefault(last_segname, dict()) \
                            .setdefault(Trace.KEY_NRCALLEE, dict()).setdefault(funcname, [0])[0] += 1
                else:
                    if last_funcname != funcname:
                        sys.stderr.write("last_funcname(%s) != funcname(%s)\n" % (last_funcname, funcname))
                        return None
                    # Current segment isn't an entry segment, so the last segment has done, pop it.
                    segstack.pop()
                    if segno == Trace.SEGNO_RETURN:
                        # Return to the segment before last segment(such as a__0[before last seg] -> b__0[last seg] -> b__return[cur seg]).
                        # We should upate time for the segment before last segment.
                        if len(segstack) != 0:
                            segstack[-1][0] = time
                        # Update callstack and calculate fulltime for function.
                        if 0 == len(callstack) or callstack[-1][1] != funcname:
                            sys.stderr.write("0 == len(callstack) or callstack[-1][1] != funcname, len(callstack)=%d\n" % (len(callstack)))
                            return None
                        traceObject.dump.setdefault(funcname, dict())   \
                            .setdefault(Trace.KEY_FULLCOST, list()).append(float(time) - float(callstack[-1][0]))
                        callstack.pop()
                    else:
                        segstack.append([time, funcname, segno])
            # len(segstack) != 0 means the program abort or exit directly, but all time info of segment has been collected.
            # For function doesn't return, then the full cost is (time,funcname_0 -> last time trace)
            while len(callstack) != 0:
                time, funcname = callstack.pop()
                traceObject.dump.setdefault(funcname, dict())   \
                    .setdefault(Trace.KEY_FULLCOST, list()).append(float(timetraces[-1][0]) - float(time))
            # Repair format for traceObject.dump.
            for fdump in traceObject.dump.values():
                fdump.setdefault(Trace.KEY_FULLCOST, list())
                for segname, segdump in fdump.items():
                    if segname != Trace.KEY_FULLCOST:
                        segdump.setdefault(Trace.KEY_NORMCOST, list())
                        segdump.setdefault(Trace.KEY_NRCALLEE, dict())
        except Exception as e:
            sys.stderr.write(e)
            sys.stderr.write("Parse time trace failed.\n")
            return None
        return traceObject

class RawTraceBuilder(TraceBuilder):
    def buildFrom(self, target: str) -> Trace|None:
        traceObject = Trace()
        headline_info, headline_pattern = list(), r"\[(.*?)\] \[(.*?)\]"
        rawtraces = [line for line in [line.strip() for line in target.strip().split('\n')] if len(line) != 0]

        # Catch head line informathon.
        for idx, trace in enumerate(rawtraces):
            matchresult = re.match(headline_pattern, trace)
            if matchresult != None:
                # headline info: (index, (command, clock))
                headline_info.append((idx, matchresult.groups()))

        # Catch rawtrace group and append it into traceObject.
        for i in range(len(headline_info)):
            begin, (command, clock) = headline_info[i][0] + 1, headline_info[i][1]
            if i == 0:
                # Init clock for later merge.
                traceObject.clock = clock
            if begin != len(rawtraces):
                timetraces = rawtraces[begin:] if i == len(headline_info) - 1 else rawtraces[begin: headline_info[i+1][0]]
                obj = TimeTraceBuilder(command, clock).buildFrom(timetraces)
                if obj is None or not traceObject.mergeTrace(obj):
                    # TODO: Return or not return None if parse failed?
                    sys.stderr.write("Append raw trace failed.\n")
        return traceObject

class TraceSerializer:
    @abstractmethod
    def serialize(self, target: Trace) -> str:
        pass

class JsonTraceSerializer(TraceSerializer):
    def serialize(self, target: Trace) -> str:
        output = dict()
        output[Trace.KEY_COMMAND] = list(target.command)
        output[Trace.KEY_CLOCK] = target.clock
        output[Trace.KEY_DUMP] = target.dump
        return json.dumps(output, indent=4)

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

    rawTrace = \
    """
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
    [command] [clock]
        1,main__0
        2,main__1
        3,func__0
        4,foo__0
        5,foo__return
    [command] [clock]
    """

    traceObj = RawTraceBuilder().buildFrom(rawTrace)
    if traceObj is None:
        sys.stderr.write("Build raw trace failed.\n")
    else:
        print(JsonTraceSerializer().serialize(traceObj))
