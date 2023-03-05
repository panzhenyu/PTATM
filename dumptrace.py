from abc import abstractmethod
import argparse, json

"""
Usage: python3 dumptrace.py [options] tracefile
Dump segment probe for interested functions of binary file.

[input format]
    See output of gentrace.py.

[output format]
    if input file has content:
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
    then we output:
        {
            "command": ["command"]
            "clock": "clock"
            "dump": {
                "main": {
                    // probe: time list
                    "main__0": [1], (main__1 - main__0)
                    "main__1": [2], (func__0 - main__1 + main__2 - func__return)
                    "main__2": [1], (main__return - main__2)
                    "callees": {
                        // function, calling num list.
                        "func": [1]
                    }
                }, // Time detail of one function.
                "func": {
                    "func__0": [2], (foo__0 - func__1 + func__1 - foo__return)
                    "func__1": [1], (func__return - func__1)
                    "callees": {
                        "foo": [1]
                    }
                },
                "foo": {
                    "foo__0": [1] (foo__return - foo__0)
                    "callees": {}
                }
            } // Dump timing information for all functions.
        } // Basic information of this dump.
"""

class Trace:
    # Global constants.
    KEY_COMMAND = "command"
    KEY_CLOCK   = "clock"
    KEY_DUMP    = "dump"
    KEY_CALLEES = "callees"

    def __init__(self) -> None:
        self.command = set()
        self.clock = str()
        self.dump = dict()

    # Modifier
    def setDump(self, dump: dict):
        self.dump = dump.copy()
        return self
    
    def addCommand(self, command: set[str]):
        self.command |= command
        return self

    def addFunctionDump(self, fname: str, fdump: dict):
        if fname not in self.dump:
            self.dump[fname] = fdump.copy()
        else:
            cur = self.dump[fname]
            for key, value in fdump.items():
                if key is Trace.KEY_CALLEES:
                    # Meger fdump['callees'] into current function.
                    curcallees = cur[key]
                    for func, callingNumList in value.items():
                        # Do merge for each callee.
                        curcallees.setdefault(func, list()).extend(callingNumList)
                else:
                    # Merge segment execution time into current function.
                    cur.setdefault(key, list()).extend(value)
        return self

    # Utils
    def genCallingGraph(self) -> dict[str:list[str]|set[str]]:
        graph = dict()
        for fname, fdump in self.dump.items():
            graph[fname] = set(fdump[Trace.KEY_CALLEES]) if Trace.KEY_CALLEES in fdump else set()
        return graph

class TraceBuilder:
    @abstractmethod
    def buildFrom(self, target) -> Trace:
        pass

class JsonTraceBuilder(TraceBuilder):
    def buildFrom(self, target: str) -> Trace:
        jsonobj = json.loads(target)


class RawTraceBuilder(TraceBuilder):
    def buildFrom(self, target: str) -> Trace:
        pass

class MultiTraceBuilder(TraceBuilder):
    def buildFrom(self, target: list[Trace]) -> Trace:
        pass

class TraceMerger:
    @staticmethod
    def mergeDump(chs_dump: dict, rhs_dump: dict):
        for func, fdump in rhs_dump.items():
            if func not in chs_dump.dump:
                chs_dump.addFunctionDump(fdump)
            else:
                chs_dump.dump[func] = Trace.mergeFucntionDump()   

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
    pass
