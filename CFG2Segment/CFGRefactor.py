from abc import abstractmethod
from . import CFGBase
import angr

class CFGRefactor:
    @abstractmethod
    def refactor(self, target) -> bool:
        pass

class FunctionRefactor(CFGRefactor):
    def __init__(self):
        # Save unsolved angr block nodes for each refactor.
        self.unresolved_block = list()
        # Save angr block nodes that aren't exist in target.node_addrs_set.
        self.nonexisted_block = list()
        # Save addr whose block cannot be attached by angr_function.get_node.
        self.emptyblock_addr = list()

    # This refactor simply considers that indirect call always returns to the next block directly.
    def refactor(self, target: CFGBase.Function):
        # Type checking.
        if not isinstance(target, CFGBase.Function):
            return False

        # Reset status.
        self.unresolved_block.clear()
        self.nonexisted_block.clear()
        self.emptyblock_addr.clear()

        # Do refactor for each node.
        for node in target.nodes.values():
            angrNode = target.angr_function.get_node(node.addr)
            if angrNode is None:
                # We cannot get node for this addr.
                # This may appear in function whose is_simprocedure is True.
                self.emptyblock_addr.append(node.addr)
            else:
                # Deal with each successor.
                for successor in angrNode.successors():
                    # Case 1: general block.
                    if isinstance(successor, angr.codenode.BlockNode):
                        successorNode = target.getNode(successor.addr)
                        if successorNode is not None:
                            # Link to this node.
                            node.appendSuccessor(successorNode)
                        else:
                            # Add it to nonexisted_block.
                            self.nonexisted_block.append(successor)
                    # Case 2: function.
                    elif isinstance(successor, angr.knowledge_plugins.functions.function.Function):
                        # Link to a function, add it to callees if successor.addr != target.addr.
                        if successor.addr == target.addr:
                            target.is_recursive = True
                        else:
                            target.callees.add(successor.addr)
                    # Case 3: other.
                    else:
                        # Add to unresolved_block.
                        self.unresolved_block.append(successor)
        return True

class FunctionalCFGRefactor(CFGRefactor):
    def __init__(self):
        # Save failed function object for each refactor.
        self.failed = list()
        # Save passed function object for each refactor.
        self.passed = list()

    def refactor(self, target: CFGBase.CFG):
        # Type checking.
        if not isinstance(target, CFGBase.CFG):
            return False
        
        # Reset status.
        result = True
        self.failed.clear()
        self.passed.clear()

        # Do refactor for each function.
        for angrFunc in target.angr_cfg.functions.values():
            # Build function object.
            func = CFGBase.Function.fromAngrFunction(angrFunc, target.angr_cfg)
            if func.is_plt or func.has_unresolved_jumps or func.is_simprocedure or 0 == func.size:
                # Ignore plt function and those who has unresolved jumps.
                self.passed.append(func)
            else:
                # Refactor the function object.
                if not FunctionRefactor().refactor(func) or not target.appendFunction(func):
                    self.failed.append(func)
                    result = False
        return result
