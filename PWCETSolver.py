
from abc import abstractmethod
import TraceTool, EVTTool

class PWCETSolver:
    def __init__(self, evt_object: EVTTool.EVT, evtcost_tag: str, result_round: int):
        self.evt_object = evt_object
        self.evtcost_tag = evtcost_tag
        self.result_round = result_round
        self.err_msg = str()

    # Generate symbolic trace for each segment.
    def solve(self, trace: TraceTool.Trace) -> bool:
        for funcname, fdump in trace.dump.items():
            for segname in fdump.keys():
                if segname == TraceTool.Trace.KEY_FULLCOST:
                    # Generate for function fullcost.
                    fullcost = trace.getFunctionFullcost(funcname)
                    fulltime = fullcost.setdefault(TraceTool.Trace.COST_TIME, list())
                    if False == self.evt_object.set_rawdata(fulltime).fit():
                        self.err_msg += self.evt_object.err_msg + "Failed to fit fulltime of function[%s]" % funcname
                        return False
                    else:
                        # Save evt arguments.
                        fullcost[self.evtcost_tag] = self.evt_object.evt_func.kwds
                        for key, value in fullcost[self.evtcost_tag].items():
                            fullcost[self.evtcost_tag][key] = round(value, self.result_round)
                else:
                    # Generate for segment normcost.
                    normcost = trace.getSegmentNormcost(funcname, segname)
                    normtime = normcost.setdefault(TraceTool.Trace.COST_TIME, list())
                    if False == self.evt_object.set_rawdata(normtime).fit():
                        self.err_msg += self.evt_object.err_msg + "Failed to fit normtime of segment[%s]" % segname
                        return False
                    else:
                        # Save evt arguments.
                        normcost[self.evtcost_tag] = self.evt_object.evt_func.kwds
                        for key, value in normcost[self.evtcost_tag].items():
                            normcost[self.evtcost_tag][key] = round(value, self.result_round)
        return True

    # Generate evt object for function.
    # This function will generate symbolic trace if necessary.
    @abstractmethod
    def genEVT(self, trace: TraceTool.Trace, funcname: str) -> EVTTool.ExtremeDistribution | None:
        pass

class SegmentListSolver(PWCETSolver):
    def __init__(self, evt_object: EVTTool.EVT, evtcost_tag: str, result_round: int, linear_evtobject: EVTTool.LinearCombinedEVT):
        super().__init__(evt_object, evtcost_tag, result_round)
        self.linear_evtobject = linear_evtobject

class GumbelSegmentListSolver(SegmentListSolver):
    COST_TAG = "gumbel"
    def __init__(self, result_round: int = 4):
        super().__init__(EVTTool.Gumbel(), GumbelSegmentListSolver.COST_TAG, result_round, EVTTool.PositiveLinearGumbel())

    # Generate evt object for function.
    # This function will generate symbolic trace if necessary.
    def genEVT(self, trace: TraceTool.Trace, funcname: str) -> EVTTool.ExtremeDistribution | None:
        pass

class ParetoSegmentListSolver(SegmentListSolver):
    COST_TAG = "pareto"
    def __init__(self, result_round: int = 4):
        super().__init__(EVTTool.Pareto(), ParetoSegmentListSolver.COST_TAG, result_round, EVTTool.PositiveLinearPareto())

    # Generate evt object for function.
    # This function will generate symbolic trace if necessary.
    def genEVT(self, trace: TraceTool.Trace, funcname: str) -> EVTTool.ExtremeDistribution | None:
        pass

class SegmentGraphSolver(PWCETSolver):
    def solve(trace: TraceTool.Trace):
        pass
