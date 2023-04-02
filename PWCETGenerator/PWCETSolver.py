
from . import EVTTool
from abc import abstractmethod
from CFG2Segment.Tool import GraphTool
from SegmentInfoCollector import TraceTool

class GeneralPWCETSolver:
    def __init__(self, extd_generator: EVTTool.EVT, symtrace_tag: str):
        # Generator who use EVT to generate ExtremeDistribution object.
        self.extd_generator = extd_generator
        # Cost tag used for trace information.
        self.symtrace_tag = symtrace_tag
        self.err_msg = str()

    # Generate symbolic trace for a cost.
    def genSymbolicCost(self, cost: dict) -> bool:
        time = cost.setdefault(TraceTool.Trace.COST_TIME, list())
        extd_func = self.extd_generator.fit(time)
        if extd_func is None:
            return False
        else:
            # Generate symbolic trace.
            cost[self.symtrace_tag] = extd_func.kwds()
        return True

    # Generate symbolic trace for all costs of segment & function.
    def genSymbolicTrace(self, trace: TraceTool.Trace) -> bool:
        for funcname, fdump in trace.dump.items():
            for segname in fdump.keys():
                if segname == TraceTool.Trace.KEY_FULLCOST:
                    # Generate symbolic trace for function fullcost.
                    if False == self.genSymbolicCost(trace.getFunctionFullcost(funcname)):
                        self.err_msg += self.extd_generator.err_msg + "Failed to fit fulltime of function[%s].\n" % funcname
                        return False
                else:
                    # Generate symbolic trace for segment normcost.
                    if False == self.genSymbolicCost(trace.getSegmentNormcost(funcname, segname)):
                        self.err_msg += self.extd_generator.err_msg + "Failed to fit normtime of segment[%s].\n" % segname
                        return False
        return True

    # Build ExtremeDistribution object from symbolic trace, return None if build failed.
    # This function will generate symbolic trace if necessary.
    def buildExtdFuncFromCost(self, cost: dict) -> EVTTool.ExtremeDistribution | None:
        if self.symtrace_tag not in cost or not EVTTool.ExtremeDistribution.validparam(cost[self.symtrace_tag]):
            if False == self.genSymbolicCost(cost):
                return None
        return self.extd_generator.gen(cost[self.symtrace_tag])

    # Generate concrete PWCETInterface object for pwcet estimate.
    # This function will generate symbolic trace if necessary.
    @abstractmethod
    def solve(self, trace: TraceTool.Trace, funcname: str) -> EVTTool.PWCETInterface | None:
        pass

class SegmentListSolver(GeneralPWCETSolver):
    def __init__(self, extd_generator: EVTTool.EVT, symtrace_tag: str, linearextd_class: EVTTool.LinearCombinedExtremeDistribution):
        super().__init__(extd_generator, symtrace_tag)
        # Class to build linear combination of extreme distribution.
        self.linearextd_class = linearextd_class

    # Generate concrete PWCETInterface object for pwcet estimate, this function will generate symbolic trace if necessary.
    # Now we define the pwcet distribution of function.
    # Assume a function F is organized by a set of segments S, where S = {Si | 1 <= i <= n}.
    # Each segment si has its norm cost, which can be described by an extreme distribution di, di ~ GEV(c, loc, scale) or GPD(c, loc, scale).
    # Each segment si also has callee set C, where C = {Cj | 1 <= j <= m}, and we have maxnr(si, Cj) indicates the max calling time of Cj.
    # Cause norm cost doesn't contains execution time of function call, we treat v(F) as execution time random variable of function F,
    # then we have v(F) = ∑di + ∑∑maxnr(si, Cj)*v(Cj), which donates a linear combination of extreme distributions.
    # For situation of calling loop, each segment within the loop should only be encountered once until a loop break.
    def solve(self, trace: TraceTool.Trace, funcname: str) -> EVTTool.LinearCombinedExtremeDistribution | None:
        if not trace.hasFunction(funcname):
            self.err_msg += "Cannot find function[%s].\n" % funcname
            return None
        call_graph, total_nrcall = trace.genCallingGraph(), {funcname: 1}
        topoIndex = {fname:idx for idx, fname in enumerate(GraphTool.topologicalSort(call_graph))}
        
        # Build linear combination of extreme distribution for funcname with calling graph.
        # 1. Collect num of total call of each function called by funcname.
        stack = [(funcname, 1)]
        while len(stack) > 0:
            cur_fname, cur_nr = stack.pop()
            segments_callees = [value[TraceTool.Trace.KEY_NRCALLEE] for key, value in trace.getFunction(cur_fname).items() 
                if key != TraceTool.Trace.KEY_FULLCOST and TraceTool.Trace.KEY_NRCALLEE in value]
            for segment_callees in segments_callees:
                for next_fname, next_nrlist in segment_callees.items():
                    # Use topo index to break loop.
                    if topoIndex[next_fname] >= topoIndex[cur_fname] or not trace.hasFunction(next_fname):
                        continue
                    next_nr = int(max(next_nrlist) * cur_nr)
                    stack.append((next_fname, next_nr))
                    total_nrcall.setdefault(next_fname, 0)
                    total_nrcall[next_fname] += next_nr
        # 2. Now all functions are unrolling, just append nr * symbolic_trace(norcost) for each segment of function.
        linear_extd = self.linearextd_class()
        for fname, nr in total_nrcall.items():
            segments_normcost = [(key, value[TraceTool.Trace.KEY_NORMCOST]) for key, value in trace.getFunction(fname).items() 
                if key != TraceTool.Trace.KEY_FULLCOST and TraceTool.Trace.KEY_NORMCOST in value]
            for segname, segment_cost in segments_normcost:
                extd_func = self.buildExtdFuncFromCost(segment_cost)
                if extd_func is None:
                    self.err_msg += "Build symbolic trace failed for segment[%s].\n" % segname
                    return None
                linear_extd.add(extd_func, nr)
        return linear_extd

class GumbelSegmentListSolver(SegmentListSolver):
    COST_TAG = "gumbel"
    def __init__(self):
        super().__init__(EVTTool.GumbelGenerator(), GumbelSegmentListSolver.COST_TAG, EVTTool.PositiveLinearGumbel)

class ExponentialParetoSegmentListSolver(SegmentListSolver):
    COST_TAG = "exponential pareto"
    def __init__(self):
        super().__init__(EVTTool.ExponentialParetoGenerator(), ExponentialParetoSegmentListSolver.COST_TAG, EVTTool.PositiveLinearExponentialPareto) 

class SegmentGraphSolver(GeneralPWCETSolver):
    # Generate concrete PWCETInterface object for pwcet estimate.
    # This function will generate symbolic trace if necessary.
    @abstractmethod
    def solve(self, trace: TraceTool.Trace, funcname: str) -> EVTTool.PWCETInterface | None:
        pass
