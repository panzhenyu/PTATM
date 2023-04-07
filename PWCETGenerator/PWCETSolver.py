
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
    def buildExtdFuncFromCost(self, cost: dict) -> EVTTool.ExtremeDistribution:
        if self.symtrace_tag not in cost or not EVTTool.ExtremeDistribution.validparam(cost[self.symtrace_tag]):
            if False == self.genSymbolicCost(cost):
                return None
        return self.extd_generator.gen(cost[self.symtrace_tag])

    # Generate concrete PWCETInterface object for pwcet estimate.
    # This function will generate symbolic trace if necessary.
    @abstractmethod
    def solve(self, trace: TraceTool.Trace, funcname: str) -> EVTTool.PWCETInterface:
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
    def solve(self, trace: TraceTool.Trace, funcname: str) -> EVTTool.LinearCombinedExtremeDistribution:
        if not trace.hasFunction(funcname):
            self.err_msg += "Cannot find function[%s].\n" % funcname
            return None

        call_graph = trace.genCallingGraph()
        topo_order = GraphTool.topologicalSort(call_graph)
        func_expr, segment_extd, func_lextd = dict(), dict(), dict()
        # Build extd of normcost for each segment, and build linear combination of extreme distribution for each function under reverse topological order.
        for fname in topo_order:
            if not trace.hasFunction(fname):
                self.err_msg += "Cannot find calling function[%s].\n" % fname
                return None
            # Build for each segment.
            linear_extd = self.linearextd_class()
            for key, value in trace.getFunction(fname).items():
                if key == TraceTool.Trace.KEY_FULLCOST:
                    continue
                # Catch segment information.
                if TraceTool.Trace.KEY_NORMCOST not in value:
                    self.err_msg += "Cannot find " + TraceTool.Trace.KEY_NORMCOST + " in segment[%s].\n" % key
                    return None
                if TraceTool.Trace.KEY_CALLINFO not in value:
                    self.err_msg += "Cannot find " + TraceTool.Trace.KEY_CALLINFO + " in segment[%s].\n" % key
                    return None
                segment_normcost = value[TraceTool.Trace.KEY_NORMCOST]
                segment_callinfo = value[TraceTool.Trace.KEY_CALLINFO]
                # Build evt trace for segment.
                segment_extd[key] = self.buildExtdFuncFromCost(segment_normcost)
                if segment_extd[key] is None:
                    self.err_msg += "Build symbolic trace failed for segment[%s].\n" % key
                    return None
                # Add segment cost into linear_extd for current function.
                linear_extd.add(segment_extd[key])
                func_expr.setdefault(fname, list()).append(key)
                # Add max function cost into linear_extd for current function.
                if 0 != len(segment_callinfo):
                    max_callseq = [callee for callee in self.getMaxCallseq(segment_callinfo, func_lextd) if callee in func_lextd]
                    linear_extd.addLinear(self.buildLinearExtd4Extdlist([func_lextd[callee] for callee in max_callseq]))
                    for callee in max_callseq:
                        func_expr.setdefault(fname, list()).extend(func_expr[callee])
            func_lextd[fname] = linear_extd
        # print(call_graph)
        # print(func_expr[funcname])
        return func_lextd[funcname]
    
    def buildLinearExtd4Extdlist(self, extd_list: list) -> EVTTool.LinearCombinedExtremeDistribution:
        linear_extd = self.linearextd_class()
        for extd in extd_list:
            if isinstance(extd, self.linearextd_class):
                if not linear_extd.addLinear(extd):
                    return None
            else:
                if not linear_extd.add(extd):
                    return None
        return linear_extd

    @abstractmethod
    def getMaxCallseq(self, callinfo: list, callee_lextd: list) -> list:
        return callinfo[-1]

class GumbelSegmentListSolver(SegmentListSolver):
    COST_TAG = "gumbel"
    def __init__(self):
        super().__init__(EVTTool.GumbelGenerator(), GumbelSegmentListSolver.COST_TAG, EVTTool.PositiveLinearGumbel)

    def maximize(self, linear_extdlist: list) -> EVTTool.LinearCombinedExtremeDistribution:
        linear_extd = self.linearextd_class()
        return linear_extd

class ExponentialParetoSegmentListSolver(SegmentListSolver):
    COST_TAG = "exponential pareto"
    def __init__(self):
        super().__init__(EVTTool.ExponentialParetoGenerator(), ExponentialParetoSegmentListSolver.COST_TAG, EVTTool.PositiveLinearExponentialPareto) 

    def maximize(self, linear_extdlist: list) -> EVTTool.LinearCombinedExtremeDistribution:
        linear_extd = self.linearextd_class()

        
        for lextd in linear_extdlist:
            lextd.genArgs()


        return linear_extd

class SegmentGraphSolver(GeneralPWCETSolver):
    # Generate concrete PWCETInterface object for pwcet estimate.
    # This function will generate symbolic trace if necessary.
    @abstractmethod
    def solve(self, trace: TraceTool.Trace, funcname: str) -> EVTTool.PWCETInterface:
        pass
