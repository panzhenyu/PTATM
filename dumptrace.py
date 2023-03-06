from abc import abstractmethod
import argparse, json, re, sys
from CFG2Segment.SFGBase import Segment, SegmentFunction

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

    def __init__(self) -> None:
        self.command = set()
        self.clock = None
        self.dump = dict()

    # Modifier
    def addFunctionDump(self, fname: str, fdump: dict):
        if fname not in self.dump:
            self.dump[fname] = fdump.copy()
        else:
            cur = self.dump[fname]
            for key, value in fdump.items():
                if key is Trace.KEY_FULLCOST:
                    # Merge full function execution time.
                    cur.setdefault(key, list()).extend(value)
                elif key not in cur:
                    # Add a new segment.
                    cur[key] = value.copy()
                else:
                    # Merge segment.
                    cur_normcost = cur[key].setdefault(Trace.KEY_NORMCOST, list())
                    cur_nrcallee = cur[key].setdefault(Trace.KEY_NRCALLEE, dict())
                    # Merge normcost for segment.
                    cur_normcost.extend(value[Trace.KEY_NORMCOST])
                    # Merge nrcallee for segment.
                    for calleeName, nrcalleeList in value[Trace.KEY_NRCALLEE]:
                        cur_nrcallee.setdefault(calleeName, list()).extend(nrcalleeList)
        return self

    # Utils
    def genCallingGraph(self) -> dict[str:list[str]|set[str]]:
        graph = dict()
        for fname, fdump in self.dump.items():
            graph[fname] = set()
            for key, value in fdump.items():
                if key is not Trace.KEY_FULLCOST:
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

"""
    1,main__0
    2,main__1
    3,func__0
    4,foo__0
    5,foo__return
    6,func__1
    7,func__return
    8,main__2
    9,main__return

    collect function: cur_time, cur_func, cur_segno
        last_appear[cur_segno] = cur_time
        parse next trace -> next_time, next_func, next_segno (None, None, None if this is no trace anymore.)
        while (have trace) and (func doesn't return) and (program doesn't exit); do
            if next_segno is not function entry segno:
                last_appear[next_segno] = next_time
                parse next trace -> next_time, next_func, next_segno
            else:
                
        done
    done
"""
class RawTraceBuilder(TraceBuilder):
    # Each item in timetraces is a time trace such as '1,main__0'.
    def appendRawTrace(self, traceObject: Trace, command: str, clock: str, timetraces: list[str]) -> bool:
        if traceObject.clock is not None and traceObject.clock != clock:
            sys.stderr.write("Clock mismatch, old is %s while new is %s.\n" % (traceObject.clock, clock))
            return False

        # Segment stack, the item format is (funcname, segno).
        segstack = list()
        try:
            for time, segname in [trace.split(',') for trace in timetraces]:
                funcname, segno = SegmentFunction.parseSegmentName(segname)
                if SegmentFunction.entrySegment(segno):
                    pass
                    # segstack.append(funcname)
                elif segno == "return":
                    pass
                    # segstack.pop()
                else:
                    # Unknown segment.
                    sys.stderr.write("Unknown segment %s with segno %s.\n" % (segname, segno))
                    return False
                
        except Exception as e:
            sys.stderr.write(e)
            sys.stderr.write("Parse time trace failed.\n")
            return False

        traceObject.command.add(command)
        return True

    def buildFrom(self, target: str) -> Trace|None:
        traceObject = Trace()
        headline_info, headline_pattern = list(), r"\[(.*?)\] \[(.*?)\]"
        rawtraces = [line for line in [line.strip() for line in target.strip().split('\n')] if len(line) != 0]

        # Catch head line informathon.
        for idx, trace in enumerate(rawtraces):
            matchresult = re.match(headline_pattern, trace)
            if matchresult is not None:
                # headline info: (index, (command, clock))
                headline_info.append((idx, matchresult.groups()))

        # Catch rawtrace group and append it into traceObject.
        for i in range(len(headline_info)):
            begin, (command, clock) = headline_info[i][0] + 1, headline_info[i][1]
            if begin != len(rawtraces):
                timetraces = rawtraces[begin:] if i == len(headline_info) - 1 else rawtraces[begin: headline_info[i+1][0]]
                if not self.appendRawTrace(traceObject, command, clock, timetraces):
                    sys.stderr.write("Append raw trace failed.\n")
                    return None

        return trace

class MultiTraceBuilder(TraceBuilder):
    def buildFrom(self, target: list[Trace]) -> Trace|None:
        pass

class TraceMerger:
    @staticmethod
    def mergeDump(chs_dump: dict, rhs_dump: dict):
        pass
        # for func, fdump in rhs_dump.items():
        #     if func not in chs_dump.dump:
        #         chs_dump.addFunctionDump(fdump)
        #     else:
        #         chs_dump.dump[func] = Trace.mergeFucntionDump()   

    @staticmethod
    def mergeTrace(chs_trace: Trace, rhs_trace: Trace) -> Trace:
        pass

class TraceSerializer:
    @abstractmethod
    def serialize(self, target: Trace) -> str:
        pass

class JsonTraceSerializer(TraceSerializer):
    def serialize(self, target: Trace) -> str:
        pass

if __name__ == "__main__":
    mode = "parse"
    files = []
    output = None


