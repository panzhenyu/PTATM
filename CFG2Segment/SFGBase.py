from lib2to3.pytree import Node
from . import CFGBase

# Save information for segment.
class Segment:
    def __init__(self, name: str, start: CFGBase.CFGNode, end: CFGBase.CFGNode|None) -> None:
        # Segment name.
        self.name = name
        # Segment addr.
        self.addr = start.addr
        # CFG object this segment belongs to.
        # self.cfg = None
        # A valid segment is that [startpoint, endpoint), so the endpoint always belongs to the next segment.
        # Start point of this segment.
        self.startpoint = start
        # End point of this segment.
        self.endpoint = end
        # Segment is an exit segment?
        self.is_exit = True if end is None else end.has_return
        # Predecessors segments.
        self.predecessors = list()
        # Successors segments.
        self.successors = list()
    
    # Modifier
    def appendSuccessor(self, segment):
        if segment not in self.successors:
            self.successors.append(segment)
            segment.predecessors.append(self)
            return self
        return None

    def removeSuccessor(self, segment):
        # Raise exception anyway.
        self.predecessors.remove(segment)
        segment.successors.remove(self)

class SegmentFunction:
    def __init__(self, func: CFGBase.Function) -> None:
        # Function object we build from.
        self.function = func
        # Function name.
        self.name = func.name
        # Function address.
        self.addr = func.addr
        # Segment set that saves segments in order.
        self.segments = list()
        # Start segment.
        self.start_segment = None
        # End segment set.
        self.end_segments = set()

    # Accessor
    def segnamePrefix(self):
        return self.function.name + "-"

    def getSegment(self, index: int):
        if index >= len(self.segments):
            return None
        return self.segments[index]

# Save information for segment flow graph.
class SFG:
    def __init__(self, cfg: CFGBase.CFG) -> None:
        # CFG object this SFG belongs to.
        self.cfg = cfg
        # A dict maps(name:str -> segment:Segment) contains all segment nodes within this SFG.
        self.segments = dict()
        # A dict maps(name:str -> function:SegmentFunction) contains all segment nodes within this SFG.
        self.functions = dict()

    # Modifier
    def appendSegment(self, segment: Segment):
        if segment.name not in self.segment:
            self.segment[segment.addr] = segment
            return True
        return False
    
    def removeSegment(self, segment: Segment):
        return self.removeSegmentByName(segment.name)
    
    def removeSegmentByName(self, name: str):
        if name in self.segments:
            self.segments.pop(name)
            return True
        return False
    
    def appendSegmentFunction(self, segmentFunc: SegmentFunction):
        name = segmentFunc.name
        if name not in self.functions:
            self.functions[name] = segmentFunc
            for seg in segmentFunc.segments:
                # Here we assume segment name within different function must be different.
                self.segments[seg.name] = seg
            return True
        return False

    def removeFunction(self, name: str):
        func = self.getFunc(name)
        if None == func:
            return False
        for segment in func.segments:
            self.removeSegment(segment)
        return True

    # Accessor
    def getAnySegment(self, name: str):
        return self.segments.get(name)

    def getFunc(self, name: str):
        return self.functions.get(name)

    def getFuncByAddr(self, addr: int):
        for func in self.functions.values():
            if func.addr == addr:
                return func
        return None
