from abc import abstractmethod
import angr
from BasicStruct import *
class AbstractCFGParser:
    @abstractmethod
    def parseFromAngrCFG(self, angrCFG: angr.analyses.cfg.cfg_fast.CFGFast, entry: int, end: int = None):
        pass
    
class GeneralCFGParser(AbstractCFGParser):
    def parseFromAngrCFG(self, angrCFG: angr.analyses.cfg.cfg_fast.CFGFast, entry: int, end: int = None):
        # Function manager.
        functions = angrCFG.functions
        # Unresolved jumps.
        unresolvedJumps = angrCFG.kb.unresolved_indirect_jumps

        # Create entry block.
        entrypoint = CFGNode.fromAngrCFGNode(angrCFG.get_any_node(entry))
        # Create CFG.
        cfg = CFG.init(angrCFG, entrypoint)
        # Function address of entry point.
        entryFunc = entrypoint.function_address

        # Start CFG copy in dfs manner.
        # A CFGNode is an endpoint node when CFGNode.function_address == entryFunc and CFGNode.has_return.
        # When CFGNode has an unresolved instruction:
        #   unresolved call: choose next block after current block as a successor.
        #   unresolved jump or next block doesn't exist: choose return point as a successor.
        # Record the calling stack, whose element contains function address and return point.
        return cfg
