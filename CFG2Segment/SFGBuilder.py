from abc import abstractmethod
from . import SFGBase

class SFGBuilder:
    @abstractmethod
    def buildFrom(self, target) -> SFGBase.SFG:
        pass

class CFGBasedBuilder(SFGBuilder):
    def buildFrom(self, target) -> SFGBase.SFG:
        pass

class AngrCFGBasedBuilder(SFGBuilder):
    def buildFrom(self, target) -> SFGBase.SFG:
        pass