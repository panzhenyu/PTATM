from abc import abstractmethod
import BasicStruct, angr

class ControlFlowRefactor:
    @abstractmethod
    def refactor(self, target) -> bool:
        pass

class FunctionalRefactor(ControlFlowRefactor):
    def __init__(self):
        # Save unsolved block nodes for each refactor.
        self.unresolved_blocknode = []

    # This refactor simply considers that indirect call always returns to the next block directly.
    def refactor(self, target: BasicStruct.Function):
        # Type checking.
        if not isinstance(target, BasicStruct.Function):
            return False

        # Reset status.
        self.unresolved_blocknode.clear()

        # Do refactor for each node.
        for node in target.nodes.values():
            angrNode = target.angr_function.get_node(node.addr)
            for successor in angrNode.successors():
                if isinstance(successor, angr.codenode.BlockNode):
                    # Link to a node.
                    assert(successor.addr in target.node_addrs_set)
                    node.appendSuccessor(target.getNode(successor.addr))
                elif isinstance(successor, angr.knowledge_plugins.functions.function.Function):
                    # Link to a function, add it to callees if successor.addr != target.addr.
                    if successor.addr == target.addr:
                        target.is_recursive = True
                    else:
                        target.callees.add(successor.addr)
                else:
                    # Add to unresolved_blocknode.
                    self.unresolved_blocknode.append(successor)
        return True

class FunctionalCFGRefactor(ControlFlowRefactor):
    def __init__(self):
        # Save failed function for each refactor.
        self.failed = []
        # Save passed function for each refactor.
        self.passed = []

    def refactor(self, target: BasicStruct.CFG):
        # Type checking.
        if not isinstance(target, BasicStruct.CFG):
            return False
        
        # Reset status.
        result = True
        self.failed.clear()
        self.passed.clear()

        # Do refactor for each function.
        for angrFunc in target.angr_cfg.functions.values():
            # Build function object.
            func = BasicStruct.Function.fromAngrFunction(angrFunc, target.angr_cfg)
            if func.is_plt or func.has_unresolved_jumps:
                # Ignore plt function and those who has unresolved jumps.
                self.passed.append(func)
            else:
                # Refactor the function object.
                if FunctionalRefactor().refactor(func):
                    target.appendFunction(func)
                else:
                    self.failed.append(func)
                    result = False
        return result
