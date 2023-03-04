from abc import abstractmethod
from . import CFGBase, SFGBase, Tool

class SFGBuilder:
    def __init__(self, max_seg) -> None:
        # Max segment num while building segment list.
        self.max_seg = max_seg

    @abstractmethod
    def build(self, target) -> bool:
        pass

    # Modifier
    def setMaxSegment(self, max_seg):
        self.max_seg = max_seg

class SFGReset:
    @abstractmethod
    def reset(self, target) -> bool:
        pass

class SegmentFunctionReset(SFGReset):
    def reset(self, target: SFGBase.SegmentFunction) -> bool:
        # Reset target members.
        target.segments = list()
        self.start_segment = None
        target.end_segments.clear()
        return True

# Make segment list for target function(SFGBase.SegmentFunction).
class FunctionalSegmentListBuilder(SFGBuilder):
    def __init__(self, max_seg) -> None:
        super().__init__(max_seg)
        # Reserve node addresses of separate points.
        self.separators = list()
        # Save addresses of error separators while make segment.
        self.error_seps = set()

    def searchSeparator(self, function: CFGBase.Function) -> list[int]:
        # Final seps.
        final = list()
        # Calculate the max num of separators.
        max_sep = self.max_seg - 1
        # Get all possible separators.
        seps = [sep.addr for sep in Tool.BlockCheckSearcher().search(function.startpoint, set(function.endpoints), lambda x: x.successors)]
        # Sort the address.
        seps.sort()
        # Shrink separators if len(sepNodes) > max_sep.
        cur_sep = len(seps)
        if cur_sep > max_sep:
            cur, step = 0, cur_sep/self.max_seg
            for _ in range(max_sep):
                cur += step
                index = int(cur) - 1
                # Ensure the safe border.
                if index < cur_sep:
                    final.append(seps[index])
        return final

    def build(self, target: SFGBase.SegmentFunction) -> bool:
        # Reset target.
        SegmentFunctionReset().reset(target)
        # Init error addr list.
        self.error_seps.clear()
        # Search separator for target function.
        self.separators = self.searchSeparator(target.function)

        # Start point is target.function.startpoint, end point is when control flow leaves this function(return or exit).
        # Thus the last segment doesn't have endpoint member(cause default is function return or call the exit/_exit).
        # Segment start from the startpoint.
        start = target.function.startpoint
        for addr in self.separators:
            end = target.function.getNode(addr)
            if end is None:
                self.error_seps.add(addr)
                continue
            target.segments.append(SFGBase.Segment(SFGBase.Segment.makeSegmentPrefix(target.function.name) + str(len(target.segments)), start, end))
            # Endpoint always belongs to the next segment.
            start = end
        # Append last segment.
        target.segments.append(SFGBase.Segment(SFGBase.Segment.makeSegmentPrefix(target.function.name) + str(len(target.segments)), start, None))
        # Make segment list.
        for i in range(len(target.segments)-1):
            target.segments[i].appendSuccessor(target.segments[i+1])
        # Initialize rest members.
        target.start_segment = target.segments[0]
        target.end_segments.add(target.segments[-1])

        return 0 == len(self.error_seps)

class ConcreteSFGReset(SFGReset):
    def reset(self, target: SFGBase.SFG) -> bool:
        # Reset target members.
        target.segments.clear()
        target.functions.clear()
        return True

# Make functional segment list for target SFG(SFGBase.SFG).
class FunctionalSFGBuilder(SFGBuilder):
    def __init__(self, max_seg, target_functions=None) -> None:
        super().__init__(max_seg)
        # Target functions to build, build all functions for target if target_functions is None.
        self.target_functions = target_functions
        # Record functions who found error separators during segment list building.
        # Map format: name:str -> addr:set[int]
        self.build_failed = dict()
        # Record functions failed at append.
        self.append_failed = set()

    def build(self, target: SFGBase.SFG) -> bool:
        # Reset target.
        ConcreteSFGReset().reset(target)
        # Prepare envs.
        segBuilder = FunctionalSegmentListBuilder(self.max_seg)
        self.build_failed.clear()
        self.append_failed.clear()
        # Build segment list for each function in cfg.
        if self.target_functions is not None:
            functions = [target.cfg.getFunc(name) for name in self.target_functions]
        else:
            functions = list(target.cfg.functions.values())
        for func in [func for func in functions if func is not None]:
            segfunc = SFGBase.SegmentFunction(func)
            # There is no matter with building failure because error seps will be ignored, so just record it.
            if not segBuilder.build(segfunc):
                self.build_failed[segfunc.name] = segBuilder.error_seps.copy()
            # Append build result(SegmentFunction) to target SFG.
            if not target.appendSegmentFunction(segfunc):
                self.append_failed.add(segfunc.name)
        return 0 == len(self.append_failed)
