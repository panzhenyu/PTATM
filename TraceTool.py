import json, re
from abc import abstractmethod
from CFG2Segment.SFGBase import SegmentFunction

# We define a trace format here.
# Note that 'time' in cost field is forced to be exist, 
# cause pareto & gumbel can only be set but appended.
"""
    {
        "command": ["command"]
        "clock": "clock",
        "dump": {
            "func0": {
                "segment__0": {
                        "normcost": {
                            "time": [1],
                            "pareto": {"c": 0, "loc": 0, "scale": 1},
                            "gumbel": {"loc": 0, "scale": 1}
                        }, 
                        "nrcallee": {
                            "callee": [1, 2],
                            other callee...
                        }
                    }, 
                }, 
                other segment...,
                "fullcost": {
                    "time": [8],
                    "pareto": {"c": 0, "loc": 0, "scale": 1},
                    "gumbel": {"loc": 0, "scale": 1}
                }
            },
            other function...
        }
    }
"""
class Trace:
    # Json trace constants.
    KEY_COMMAND     = "command"
    KEY_CLOCK       = "clock"
    KEY_DUMP        = "dump"
    KEY_NORMCOST    = "normcost"
    KEY_NRCALLEE    = "nrcallee"
    KEY_FULLCOST    = "fullcost"

    # Cost field constants.
    COST_TIME       = "time"

    def __init__(self) -> None:
        self.command = set()
        self.clock = None
        self.dump = dict()

    # Accessor, note that these accessors may modify dump if target function/segment is not exist.
    def getFunction(self, funcname: str) -> dict:
        return self.dump.setdefault(funcname, dict())
    
    def getFunctionFullcost(self, funcname: str) -> dict:
        return self.getFunction(funcname).setdefault(Trace.KEY_FULLCOST, dict())

    def getSegment(self, funcname: str, segname: str) -> dict:
        return self.getFunction(funcname).setdefault(segname, dict())

    def getSegmentNormcost(self, funcname: str, segname: str) -> dict:
        return self.getSegment(funcname, segname).setdefault(Trace.KEY_NORMCOST, dict())

    def getSegmentNrcallee(self, funcname: str, segname: str) -> dict:
        return self.getSegment(funcname, segname).setdefault(Trace.KEY_NRCALLEE, dict())

    def genCallingGraph(self) -> dict[str:list[str]|set[str]]:
        graph = dict()
        for fname, fdump in self.dump.items():
            graph[fname] = set()
            for key, value in fdump.items():
                if key != Trace.KEY_FULLCOST:
                    graph[fname] |= set(value[Trace.KEY_NRCALLEE].keys())
        return graph

    def hasFunction(self, funcname: str) -> bool:
        return funcname in self.dump

class TraceFiller:
    def __init__(self, trace: Trace) -> None:
        self.trace = trace
        self.err_msg = str()

    # Fill self.trace with target.
    @abstractmethod
    def fill(self, target) -> bool:
        pass

class DumpFiller(TraceFiller):
    def __init__(self, trace: Trace) -> None:
        self.trace = trace

    def fill(self, target=None) -> bool:
        # Repair format for self.trace.dump.
        for fdump in self.trace.dump.values():
            fdump.setdefault(Trace.KEY_FULLCOST, dict()).setdefault(Trace.COST_TIME, list())
            for segname, segdump in fdump.items():
                if segname != Trace.KEY_FULLCOST:
                    segdump.setdefault(Trace.KEY_NORMCOST, dict()).setdefault(Trace.COST_TIME, list())
                    segdump.setdefault(Trace.KEY_NRCALLEE, dict())
        return True

class TraceObjectFiller(TraceFiller):
    def __init__(self, trace: Trace) -> None:
        super().__init__(trace)

    # We assume target is a valid trace object.
    def fill(self, target: Trace) -> bool:
        if target.clock == None or (self.trace.clock != None and self.trace.clock != target.clock):
            self.err_msg += "clock mismatch for target(%s) and self.trace(%s)\n" % (target.clock, self.trace.clock)
            return False

        self.trace.command |= target.command
        self.trace.clock = target.clock
        for fname, fdump in target.dump.items():
            if fname not in self.trace.dump:
                self.trace.dump[fname] = fdump.copy()
            else:
                cur = self.trace.getFunction(fname)
                for key, value in fdump.items():
                    if key == Trace.KEY_FULLCOST:
                        # Merge full function execution time.
                        self.trace.getFunctionFullcost(fname).setdefault(Trace.COST_TIME, list()).extend(value[Trace.COST_TIME])
                    elif key in cur:
                        # Merge segment.
                        self.trace.getSegmentNormcost(fname, key).setdefault(Trace.COST_TIME, list()) \
                            .extend(value[Trace.KEY_NORMCOST][Trace.COST_TIME])
                        cur_nrcallee = self.trace.getSegmentNrcallee(fname, key)
                        # Merge nrcallee for segment.
                        for calleeName, nrcalleeList in value[Trace.KEY_NRCALLEE].items():
                            cur_nrcallee.setdefault(calleeName, list()).extend(nrcalleeList)
                    else:
                        # Add a new segment.
                        cur[key] = value.copy()
        # There is no need to fill dump anymore, cause self.trace and target are valid.
        return True

class RawTraceStringFiller(TraceFiller):
    """
        A simple raw trace:
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
        ...
    """
    def __init__(self, trace: Trace) -> None:
        super().__init__(trace)

    def buildFromSingleRawTrace(self, command: str, clock: str, timetraces: list[str]) -> Trace|None:
        # Init trace object.
        traceObject = Trace()
        traceObject.command.add(command)
        traceObject.clock = clock
        # Segment stack contains items whose format is (time, funcname, segno, and callstack contains items of func entry and func return, 
        # whose format is as same as segment stack.
        segstack, callstack = list(), list()
        try:
            timetraces = [trace.split(',') for trace in timetraces]
            for time, segname in timetraces:
                funcname, segno = SegmentFunction.parseSegmentName(segname)
                last_time, last_funcname, last_segno = segstack[-1] if len(segstack) != 0 else (None, None, None)
                last_segname = SegmentFunction.makeSegmentName(last_funcname, last_segno) if last_funcname != None else None

                # A piece of last segment has been executed, add time cost to it.
                if last_segname != None:
                    traceObject.getSegmentNormcost(last_funcname, last_segname) \
                        .setdefault(Trace.COST_TIME, [0])[0] += float(time) - float(last_time)

                if SegmentFunction.entrySegment(segno):
                    # If the last time trace is a function call, there is meaningless to record it(last function will be reserved without any timing information).
                    if time != timetraces[-1][0]:
                        # Entry segment meas a function call.
                        segstack.append([time, funcname, segno])
                        callstack.append((time, funcname))
                        if last_segname != None:
                            traceObject.getSegmentNrcallee(last_funcname, last_segname).setdefault(funcname, [0])[0] += 1
                else:
                    if last_funcname != funcname:
                        self.err_msg += "last_funcname(%s) != funcname(%s)\n" % (last_funcname, funcname)
                        return None
                    # Current segment isn't an entry segment, so the last segment has done, pop it.
                    segstack.pop()
                    if SegmentFunction.returnSegment(segno):
                        # Return to the segment before last segment(such as a__0[before last seg] -> b__0[last seg] -> b__return[cur seg]).
                        # We should upate time for the segment before last segment.
                        if len(segstack) != 0:
                            segstack[-1][0] = time
                        # Update callstack and calculate fulltime for function.
                        if 0 == len(callstack) or callstack[-1][1] != funcname:
                            self.err_msg += "0 == len(callstack) or callstack[-1][1] != funcname, len(callstack)=%d\n" % (len(callstack))
                            return None
                        traceObject.getFunctionFullcost(funcname)   \
                            .setdefault(Trace.COST_TIME, list()).append(float(time) - float(callstack[-1][0]))
                        callstack.pop()
                    else:
                        segstack.append([time, funcname, segno])
            # len(segstack) != 0 means the program abort or exit directly, but all time info of segment has been collected.
            # For function doesn't return, then the full cost is (time,funcname_0 -> last time trace)
            while len(callstack) != 0:
                time, funcname = callstack.pop()
                traceObject.getFunctionFullcost(funcname)   \
                    .setdefault(Trace.COST_TIME, list()).append(float(timetraces[-1][0]) - float(time))
            # Repair format for traceObject.dump.
            DumpFiller(traceObject).fill()
        except Exception as _:
            self.err_msg += "Parse time trace failed.\n"
            return None
        return traceObject

    def fill(self, target: str) -> bool:
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
            if begin != len(rawtraces):
                timetraces = rawtraces[begin:] if i == len(headline_info) - 1 else rawtraces[begin: headline_info[i+1][0]]
                # Build trace object from timetraces.
                traceObject = self.buildFromSingleRawTrace(command, clock, timetraces)
                # Append trace object into self.trace with TraceObjectFiller.
                if traceObject is None or not TraceObjectFiller(self.trace).fill(traceObject):
                    # TODO: Return or not return None if parse failed?
                    self.err_msg += "Append raw trace failed.\n"
        return True

class JsonTraceFiller(TraceFiller):
    def __init__(self, trace: Trace) -> None:
        super().__init__(trace)

    def fill(self, target: str) -> bool:
        jsonobj = json.loads(target)
        if Trace.KEY_COMMAND not in jsonobj or Trace.KEY_CLOCK not in jsonobj or Trace.KEY_DUMP not in jsonobj  \
            or not isinstance(jsonobj[Trace.KEY_COMMAND], list) or not isinstance(jsonobj[Trace.KEY_CLOCK], str) \
            or not isinstance(jsonobj[Trace.KEY_DUMP], dict):
            self.err_msg += "Json trace format error.\n"
            return False
        traceObject = Trace()
        traceObject.command = set(jsonobj[Trace.KEY_COMMAND])
        traceObject.clock = jsonobj[Trace.KEY_CLOCK]
        traceObject.dump = jsonobj[Trace.KEY_DUMP].copy()
        DumpFiller(traceObject).fill()
        return TraceObjectFiller(self.trace).fill(traceObject)

class TraceSerializer:
    @abstractmethod
    def serialize(self, target: Trace) -> str:
        pass

class JsonTraceSerializer(TraceSerializer):
    def __init__(self, indent=None) -> None:
        super().__init__()
        self.indent = indent

    def serialize(self, target: Trace) -> str:
        output = dict()
        output[Trace.KEY_COMMAND] = list(target.command)
        output[Trace.KEY_CLOCK] = target.clock
        output[Trace.KEY_DUMP] = target.dump
        return json.dumps(output, indent=self.indent)

class TraceStripper:
    def __init__(self, trace: Trace) -> None:
        self.trace = trace
        self.err_msg = str()

    @abstractmethod
    def strip(self) -> bool:
        pass

# Clear all Trace.COST_TIME fields.
class CostTimeStripper(TraceStripper):
    def __init__(self, trace: Trace) -> None:
        super().__init__(trace)
    
    def strip(self) -> bool:
        for fdump in self.trace.dump.values():
            for segname, value in fdump.items():
                if segname != Trace.KEY_FULLCOST:
                    value[Trace.KEY_NORMCOST][Trace.COST_TIME].clear()
                else:
                    value[Trace.COST_TIME].clear()
        return True

# Shrink function list in KEY_NRCALLEE to one max element.
class CalleeMaximizeStripper(TraceStripper):
    def __init__(self, trace: Trace) -> None:
        super().__init__(trace)

    def strip(self) -> bool:
        for fdump in self.trace.dump.values():
            for segname, value in fdump.items():
                if segname != Trace.KEY_FULLCOST:
                    for nrlist in value[Trace.KEY_NRCALLEE].values():
                        max_val = max(nrlist)
                        nrlist.clear()
                        nrlist.append(max_val)
        return True
