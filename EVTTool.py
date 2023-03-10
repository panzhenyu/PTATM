import statsmodels.tsa.stattools as stattools
from abc import abstractmethod
from scipy.stats import gamma, genpareto, genextreme, cramervonmises

# We can generate a pwcet estimate/plot from a PWCETInterface.
class PWCETInterface:
    # Return a value with exceedance probability(exceed_prob).
    @abstractmethod
    def isf(self, exceed_prob: float) -> float:
        pass

    # Return an expression.
    @abstractmethod
    def expression(self) -> str:
        return str()

class ExtremeDistribution(PWCETInterface):
    PARAM_SHAPE = "c"
    PARAM_LOC   = "loc"
    PARAM_SCALE = "scale"

    @staticmethod
    def validparam(params: dict) -> bool:
        return ExtremeDistribution.PARAM_SHAPE in params and ExtremeDistribution.PARAM_LOC in params and ExtremeDistribution.PARAM_SCALE in params

    def __init__(self, ext_class, params: dict) -> None:
        super().__init__()
        # Here ext_class is original generator from scipy.stat.
        self.ext_class = ext_class
        # Here ext_func is original extreme distribution object from scipy.stat
        self.gen(params)

    # Re-generate self.ext_func attribute with params.
    def gen(self, params: dict):
        c = params[ExtremeDistribution.PARAM_SHAPE]
        loc = params[ExtremeDistribution.PARAM_LOC]
        scale = params[ExtremeDistribution.PARAM_SCALE]
        self.ext_func = self.ext_class(c=c, loc=loc, scale=scale)
        return self

    # Return self.ext_func.kwds.
    def kwds(self) -> dict:
        return self.ext_func.kwds

    def isf(self, exceed_prob: float) -> float:
        return self.ext_func.isf(exceed_prob)

    def expression(self) -> str:
        kwds = self.ext_func.kwds
        return "(loc=%s,scale=%s)" % (str(round(kwds["loc"], 4)), str(round(kwds["scale"], 4)))

class GEV(ExtremeDistribution):
    def __init__(self, params: dict) -> None:
        super().__init__(genextreme, params)

    def expression(self) -> str:
        return "GEV" + super().expression()

class GPD(ExtremeDistribution):
    def __init__(self, params: dict) -> None:
        super().__init__(genpareto, params)

    def expression(self) -> str:
        return "GPD" + super().expression()

class LinearCombinedExtremeDistribution(PWCETInterface):
    def __init__(self) -> None:
        # A dict maps extd function(ExtremeDistribution object) to it's weight.
        self.weighted_extdfunc = dict()

    def add(self, extd_func: ExtremeDistribution, weight: int = 1) -> bool:
        self.weighted_extdfunc.setdefault(extd_func, 0)
        self.weighted_extdfunc[extd_func] += weight
        return True

    def clear(self):
        self.weighted_extdfunc.clear()

    def expression(self) -> str:
        expr = str()
        for extd_func, weight in self.weighted_extdfunc.items():
            expr += str(weight) + '*' + extd_func.expression() + '+'
        return expr[:-1]

class PositiveLinearGumbel(LinearCombinedExtremeDistribution):
    def __init__(self) -> None:
        super().__init__()

    def add(self, extd_func: GEV, weight: int = 1) -> bool:
        if not isinstance(extd_func, GEV) or weight <= 0 or extd_func.kwds()[ExtremeDistribution.PARAM_SHAPE] != 0:
            return False
        return super().add(extd_func, weight)

    # Return a value with exceedance probability(exceed_prob).
    def isf(self, exceed_prob: float) -> float:
        ans = 0.0
        for extd_func, weight in self.weighted_extdfunc.items():
            ans += weight * extd_func.isf(exceed_prob)
        return ans

# ExponentialPareto xi ~ GPD(c=0, loc=ui, scale=σi) ~ E(ui, σi), we assume ui > 0 and σi > 0 for i in 1 ~ n.
# Let yi = xi-ui/σi ~ E(0, 1), then ∑yi ~ Gamma(a=n, loc=0, scale=1).
# If p(∑yi < k) = pk, cause ∑yi = ∑[(xi-ui)/σi], then ∑(xi-ui) / max{σi} <= ∑yi <= ∑(xi-ui) / min{σi}.
# Thus, min{σi} * ∑yi + ∑ui <= ∑xi <= max{σi} * ∑yi + ∑ui and p(∑xi < max{σi}*k+∑ui) >= pk
# Finally, for exceedance probability ep = 1 - pk, cause  p(∑yi >= k) = 1 - pk = ep, then p(∑xi >= max{σi}*k+∑ui) <= 1 - pk = ep,
# we can promise the probability of pwcet=max{σi}*k+∑ui is smaller than the given probability ep.
# For weighted exponential variable x,  x ~ E(u, σ), then weight*x ~ E(u, weight*σ).
class PositiveLinearExponentialPareto(LinearCombinedExtremeDistribution):
    def __init__(self) -> None:
        super().__init__()
        # Attributes works for isf according to self.weighted_evtfunc.
        # Those attrs should be re-generate if self.weighted_evtfunc is changed.
        self.gamma_func = None
        self.max_scale = None
        self.sum_loc = None
        self.should_gen = True

    # Generate helper attrs: gamma_func, max_scale, sum_loc.
    def genHelper(self):
        self.gamma_func = gamma(a=len(self.weighted_extdfunc), loc=0, scale=1)
        self.max_scale = -1
        self.sum_loc = 0
        for extd_func, weight in self.weighted_extdfunc.items():
            kwds = extd_func.kwds()
            self.max_scale = max(self.max_scale, weight*kwds[ExtremeDistribution.PARAM_SCALE])
            self.sum_loc += kwds[ExtremeDistribution.PARAM_LOC]
        self.should_gen = False

    def add(self, extd_func: GPD, weight: int = 1) -> bool:
        if not isinstance(extd_func, GPD) or weight <= 0 or extd_func.kwds()[ExtremeDistribution.PARAM_SHAPE] != 0:
            return False
        return super().add(extd_func, weight)

    # Return a value with exceedance probability(exceed_prob).
    def isf(self, exceed_prob: float) -> float:
        if self.should_gen:
            self.genHelper()
        return self.max_scale*self.gamma_func.isf(exceed_prob) + self.sum_loc

# A theory tool that helps to generate ExtremeDistribution object.
class EVT:
    def __init__(self) -> None:
        # A list saves extreme samples.
        self.ext_data = list()
        # Save error message.
        self.err_msg = str()

    # Returns none if fit faled, otherwise returns an ExtremeDistribution object. 
    @abstractmethod
    def fit(self, raw_data: list[float]) -> ExtremeDistribution|None:
        # pick raw samples until we pass kpss,bds,lrd test -> pick extreme value & EVT fit until we pass cvm test.
        return None

    @abstractmethod
    # Generate ExtremeDistribution object with params.
    def gen(self, params: dict) -> ExtremeDistribution|None:
        pass

    # Util.
    # Stationarity test for raw data.
    def kpss(self, raw_data: list[float]):
        return stattools.kpss(raw_data)

    # Independent and identically distributed test for raw data.
    def bds(self, raw_data: list[float]):
        return stattools.bds(raw_data)

    # Long range dependence test.
    def lrd(self, raw_data: list[float]):
        # TODO: fill this function.
        pass

    # Test for goodness of fit of a cumulative distribution function.
    def cvm(self, ext_data: list[float], ext_func):
        return cramervonmises(ext_data, ext_func.cdf)

# Generate GEV distribution witl EVT tool.
class GEVGenerator(EVT):
    MIN_NRSAMPLE = 2

    def __init__(self, fix_c = None) -> None:
        super().__init__()
        self.fix_c = fix_c

    @staticmethod
    def BM(data: list[float], bs: int) -> list[float]:
        ext_vals, nr_sample = list(), len(data)
        for i in range(nr_sample//bs + 1):
            s = i * bs
            e = s + bs
            if s >= nr_sample:
                break
            ext_vals.append(max(data[s:] if e > nr_sample else data[s:e]))
        return ext_vals

    def fit(self, raw_data: list[float]) -> ExtremeDistribution|None:
        # Pick raw samples until we pass kpss,bds,lrd test -> pick extreme value & EVT fit until we pass cvm test.
        if len(raw_data) < GEVGenerator.MIN_NRSAMPLE:
            self.err_msg = "Too few samples[%d] to fit.\n" % len(raw_data)
            return None
        if max(raw_data) <= 0:
            self.err_msg = "Max(raw_data)[%f]<=0.\n" % max(raw_data)
            return None

        # Use BM to filter ext_data.
        max_bs = len(raw_data) // GEVGenerator.MIN_NRSAMPLE
        self.ext_data = GEVGenerator.BM(raw_data, max_bs)

        # TODO: pass test.

        # Fit args for evt class and build evt function.
        if self.fix_c is None:
            c, loc, scale = genextreme.fit(self.ext_data)
        else:
            c, loc, scale = genextreme.fit(self.ext_data, f0=self.fix_c)
        return self.gen({ExtremeDistribution.PARAM_SHAPE: c, ExtremeDistribution.PARAM_LOC: loc, ExtremeDistribution.PARAM_SCALE: scale})

    def gen(self, params: dict) -> ExtremeDistribution|None:
        if not ExtremeDistribution.validparam(params):
            return None
        return GEV(params)

# Generate GPD distribution witl EVT tool.
class GPDGenerator(EVT):
    MIN_NRSAMPLE = 1

    def __init__(self, fix_c = None) -> None:
        super().__init__()
        self.fix_c = fix_c

    @staticmethod
    def POT(data: list[float], nr_ext: int) -> list[float]:
        nr_sample = len(data)
        if nr_ext < 0 or nr_ext >= nr_sample:
            return data[:]
        data = data.copy()
        data.sort()
        return data[-nr_ext:]

    def fit(self, raw_data: list[float]) -> ExtremeDistribution|None:
        # Pick raw samples until we pass kpss,bds,lrd test -> pick extreme value & EVT fit until we pass cvm test.
        if len(raw_data) < GPDGenerator.MIN_NRSAMPLE:
            self.err_msg += "Too few samples[%d] to fit.\n" % len(raw_data)
            return None
        if max(raw_data) <= 0:
            self.err_msg += "Max(raw_data)[%f]<=0.\n" % max(raw_data)
            return None

        # Use POT to filter ext_data.
        self.ext_data = GPDGenerator.POT(raw_data, 4)

        # TODO: pass test.

        # Fit args for evt class and build evt function.
        if self.fix_c is None:
            c, loc, scale = genpareto.fit(self.ext_data)
        else:
            c, loc, scale = genpareto.fit(self.ext_data, f0=self.fix_c)
        return self.gen({ExtremeDistribution.PARAM_SHAPE: c, ExtremeDistribution.PARAM_LOC: loc, ExtremeDistribution.PARAM_SCALE: scale})

    def gen(self, params: dict) -> ExtremeDistribution|None:
        if not ExtremeDistribution.validparam(params):
            return None
        return GPD(params)

class GumbelGenerator(GEVGenerator):
    def __init__(self) -> None:
        super().__init__(0)

class ExponentialParetoGenerator(GPDGenerator):
    def __init__(self) -> None:
        super().__init__(0)
