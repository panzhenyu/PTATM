from abc import abstractmethod
from . import SFGBase

class SFGBuilder:
    @abstractmethod
    def build(self, target) -> bool:
        pass

class FunctionalSegmentListBuilder(SFGBuilder):
    def __init__(self, max_seg) -> None:
        # Max segment num while building segment list.
        self.max_seg = max_seg
        # Reserve node addresses of separate points.
        self.separators = set()
        # Save error separator points while make segment.
        self.error_seps = set()

    def searchSeparator(self) -> None:
        pass

    def build(self, target: SFGBase.SegmentFunction) -> bool:
        # Search separator for target function.
        self.searchSeparator()
        # Sort the address.
        sorted_seps = sorted(self.separators)
        # Init error addr list.
        self.error_seps.clear()

        # Start point is target.function.startpoint, end point is when control flow leaves this function(return or exit).
        # Thus the last segment doesn't have endpoint member(cause default is function return or call the exit/_exit).
        # Segment start from the startpoint.
        start = target.function.startpoint
        for addr in sorted_seps:
            end = target.function.getNode(addr)
            if end is None:
                self.error_seps.add(addr)
                continue
            target.segments.append(SFGBase.Segment(target.segnamePrefix() + str(len(target.segments)), start, end))
            # Endpoint always belongs to the next segment.
            start = end
        # Append last segment.
        target.segments.append(SFGBase.Segment(target.segnamePrefix() + str(len(target.segments)), start, None))
        # Make segment list.
        for i in range(len(target.segments)-1):
            target.segments[i].appendSuccessor(self.segments[i+1])
        # Initialize rest members.
        target.start_segment = target.segments[0]
        target.end_segments.add(target.segments[-1])

        return 0 == len(self.error_seps)

class FunctionalSFGBuilder(SFGBuilder):
    def build(self, target: SFGBase.SFG) -> bool:
        pass
