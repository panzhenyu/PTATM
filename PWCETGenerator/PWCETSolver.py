
from . import EVTTool
from abc import abstractmethod
from collections import Counter
from CFG2Segment.Tool import GraphTool
from SegmentInfoCollector import TraceTool

"""
    We generate symbolic trace with EVT tools like this:
    {
        "command": ["command"], 
        "clock": "clock", 
        "dump": {
            "main": {
                "main__0": {
                    "normcost": {
                        "time": [1], (main__1 - main__0)
                        "pareto": dict of pareto args, 
                        ...
                    }, 
                    "callinfo": []
                },
                ...
                "fullcost": {
                    "time": [8], (main__return - main__0),
                    "pareto": dict of pareto args, 
                    "expr": save expression for current function.
                    ...
                }
            }, 
            ...
        }
    }
"""
class GeneralPWCETSolver:
    TAG_EXPR = 'expr'
    def __init__(self, extd_generator: EVTTool.EVT, symtrace_tag: str):
        # Generator who use EVT to generate ExtremeDistribution object.
        self.extd_generator = extd_generator
        # Cost tag used for trace information.
        self.symtrace_tag = symtrace_tag
        self.err_msg = str()

    # Build ExtremeDistribution object from symbolic trace, return None if build failed.
    # This function will generate symbolic trace if necessary.
    def extd4Normcost(self, cost: dict, force: bool) -> EVTTool.ExtremeDistribution:
        if force or self.symtrace_tag not in cost or not EVTTool.ExtremeDistribution.validparam(cost[self.symtrace_tag]):
            time = cost.setdefault(TraceTool.Trace.COST_TIME, list())
            extd_func = self.extd_generator.fit(time)
            if extd_func is not None:
                cost[self.symtrace_tag] = extd_func.kwds()
            else:
                return None
        return self.extd_generator.gen(cost[self.symtrace_tag])

    # Generate concrete PWCETInterface object for pwcet estimate.
    # This function will generate symbolic trace if necessary.
    @abstractmethod
    def solve(self, trace: TraceTool.Trace, force: bool) -> bool:
        pass

class SegmentListSolver(GeneralPWCETSolver):
    def __init__(self, extd_generator: EVTTool.EVT, symtrace_tag: str, linearextd_class):
        super().__init__(extd_generator, symtrace_tag)
        # Class to build linear combination of extreme distribution.
        self.linearextd_class = linearextd_class
        self.call_graph = dict()
        self.topo_order = list()
        self.func_expr = dict()
        self.segment_extd = dict()

    # Generate concrete PWCETInterface object for pwcet estimate, this function will generate symbolic trace if necessary.
    # Now we define the pwcet distribution of function.
    # Assume a function F is organized by a set of segments S, where S = {Si | 1 <= i <= n}.
    # Each segment si has its norm cost, which can be described by an extreme distribution di, di ~ GEV(c, loc, scale) or GPD(c, loc, scale).
    # Each segment si also has callee set C, where C = {Cj | 1 <= j <= m}, and we have maxnr(si, Cj) indicates the max calling time of Cj.
    # Cause norm cost doesn't contains execution time of function call, we treat v(F) as execution time random variable of function F,
    # then we have v(F) = ∑di + ∑∑maxnr(si, Cj)*v(Cj), which donates a linear combination of extreme distributions.
    # For situation of calling loop, each segment within the loop should only be encountered once until a loop break.
    def solve(self, trace: TraceTool.Trace, force: bool) -> bool:
        self.call_graph = trace.genCallingGraph()
        self.topo_order = GraphTool.topologicalSort(self.call_graph)
        self.func_expr = dict()
        self.segment_extd = dict()

        # Build expr for each function and build extd for each segment.
        for findex, fname in enumerate(self.topo_order):
            if not trace.hasFunction(fname):
                self.err_msg += "Cannot find calling function[%s]." % fname
                return False
            ftrace = trace.getFunction(fname)
            # Try to get expr from history.
            cur_expr = ftrace[TraceTool.Trace.KEY_FULLCOST].get(GeneralPWCETSolver.TAG_EXPR, dict())
            # Whether we should rebuild the expr.
            rebuild_expr = force or not isinstance(cur_expr, dict) or len(cur_expr) == 0
            if rebuild_expr:
                cur_expr.clear()
            for key, value in ftrace.items():
                if key == TraceTool.Trace.KEY_FULLCOST:
                    continue
                # Catch segment information.
                if TraceTool.Trace.KEY_NORMCOST not in value:
                    self.err_msg += "Cannot find " + TraceTool.Trace.KEY_NORMCOST + " in segment[%s]." % key
                    return False
                if TraceTool.Trace.KEY_CALLINFO not in value:
                    self.err_msg += "Cannot find " + TraceTool.Trace.KEY_CALLINFO + " in segment[%s]." % key
                    return False
                segment_normcost = value[TraceTool.Trace.KEY_NORMCOST]
                segment_callinfo = value[TraceTool.Trace.KEY_CALLINFO]
                # Build evt trace for segment.
                self.segment_extd[key] = self.extd4Normcost(segment_normcost, force)
                if self.segment_extd[key] is None:
                    self.err_msg += "Build symbolic trace failed for segment[%s]." % key
                    return False
                # Add segment cost to cur_expr if we need to rebuild it.
                if not rebuild_expr:
                    continue
                cur_expr.setdefault(key, 0)
                cur_expr[key] += 1
                # Add function cost to cur_expr if exists.
                if 0 != len(segment_callinfo):
                    # Find max function cost.
                    max_callseq = self.maxCallseq(segment_callinfo, self.topo_order[:findex])
                    # Add function cost to cur_expr.
                    for callee, nr_callee in max_callseq.items():
                        for segname, nr_seg in self.func_expr[callee].items():
                            cur_expr.setdefault(segname, 0)
                            cur_expr[segname] += nr_seg * nr_callee
            if rebuild_expr:
                # Save expr into trace, cause we rebuild it.
                ftrace[TraceTool.Trace.KEY_FULLCOST][GeneralPWCETSolver.TAG_EXPR] = cur_expr
            # Save expr into func_expr.
            self.func_expr[fname] = cur_expr
        return True

    def lextd4Expr(self, expr: list) -> EVTTool.LinearCombinedExtremeDistribution:
        linear_extd = self.linearextd_class()
        for segname, nr_seg in expr.items():
            if segname not in self.segment_extd or not linear_extd.add(self.segment_extd[segname], nr_seg):
                return None
        return linear_extd

    def lextd4Function(self, funcname: str) -> EVTTool.LinearCombinedExtremeDistribution:
        return None if funcname not in self.func_expr else self.lextd4Expr(self.func_expr[funcname])

    # Return a dict about call seq, the key is callee, the value is nr_callee.
    def maxCallseq(self, callinfo: list, valid_callees: list) -> dict:
        max_count = {callee: 0 for callee in valid_callees}
        for callseq in callinfo:
            for callee, nr_callee in dict(Counter(callseq)).items():
                if callee in max_count and max_count[callee] < nr_callee:
                    max_count[callee] = nr_callee
        return max_count

class GumbelSegmentListSolver(SegmentListSolver):
    COST_TAG = "gumbel"
    def __init__(self):
        super().__init__(EVTTool.GumbelGenerator(), GumbelSegmentListSolver.COST_TAG, EVTTool.PositiveLinearGumbel)

class ExponentialParetoSegmentListSolver(SegmentListSolver):
    COST_TAG = "expon"
    def __init__(self):
        super().__init__(EVTTool.ExponentialParetoGenerator(), ExponentialParetoSegmentListSolver.COST_TAG, EVTTool.PositiveLinearExponentialPareto) 

    # def lextd4Expr(self, expr: dict, segment_extd: list) -> EVTTool.LinearCombinedExtremeDistribution:
    #     linear_extd = self.linearextd_class()
    #     for segname, nr_seg in expr.items():
    #         if not linear_extd.add(segment_extd[segname], nr_seg):
    #             return None
    #     return linear_extd

    # def maxCallseq(self, callinfo: list, callee_lextd: list) -> list:
    #     for callseq in callinfo:
    #         pass
    #     return callinfo[-1]

# class SegmentGraphSolver(GeneralPWCETSolver):
#     # Generate concrete PWCETInterface object for pwcet estimate.
#     # This function will generate symbolic trace if necessary.
#     @abstractmethod
#     def solve(self, trace: TraceTool.Trace, force: bool) -> bool:
#         pass
