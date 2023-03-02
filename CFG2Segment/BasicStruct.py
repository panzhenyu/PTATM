from abc import abstractmethod
from lib2to3.pytree import Node
import angr
from more_itertools import last

# Save information for basic block.
# class Block:
#     @staticmethod
#     def init(addr, arch, bytes, disassembly, instruction_addrs, instructions, size):
#         block = Block()
#         # First instruction address.
#         block.addr = addr
#         # Instruction arch.
#         block.arch = arch
#         # Bytes value of instructions.
#         block.bytes = bytes
#         # Disassembly code of instructions.
#         block.disassembly = disassembly
#         # Instruction addrs.
#         block.instruction_addrs = instruction_addrs
#         # Instruction num.
#         block.instructions = instructions
#         # Basic block size.
#         block.size = size
#         return block

#     @staticmethod
#     def fromAngrBlock(angr_block: angr.block.Block):
#         block = Block()
#         block.addr = angr_block.addr
#         block.arch = angr_block.arch
#         block.bytes = angr_block.bytes
#         block.disassembly = angr_block.disassembly
#         block.instruction_addrs = angr_block.instruction_addrs
#         block.instructions = angr_block.instructions
#         return block
    
#     def copy(self):
#         blk = Block()
#         blk.addr = self.addr
#         blk.arch = self.arch.copy()
#         blk.bytes = self.bytes
#         blk.disassembly = self.disassembly
#         blk.instruction_addrs = self.instruction_addrs.copy()
#         blk.instructions = self.instructions
#         blk.size = self.size
#         return blk

# Save flow related information for basic block.
class CFGNode:
    @staticmethod
    def init(name, block, block_id, has_return, is_syscall, function_address):
        node = CFGNode()
        # Basic block name.
        node.name = name
        # Basic block detail.
        node.block = block
        # Basic block id.
        node.block_id = block_id
        # Basic block address.
        node.addr = node.block.addr
        # Basic block size.
        node.size = node.block.size
        # Basic block is a system call?
        node.is_syscall = is_syscall
        # Basic block has return?
        node.has_return = has_return
        # Function address.
        node.function_address = function_address
        # Predecessor CFG nodes.
        node.predecessors = []
        # Successor CFG nodes.
        node.successors = []
        return node

    @staticmethod
    def fromAngrCFGNode(angr_node: angr.knowledge_plugins.cfg.cfg_node.CFGNode):
        node = CFGNode()
        node.name = angr_node.name
        node.block = angr_node.block
        node.block_id = angr_node.block_id
        node.addr = node.block.addr
        node.size = node.block.size
        node.is_syscall = angr_node.is_syscall
        node.has_return = angr_node.has_return
        node.function_address = angr_node.function_address
        node.predecessors = []
        node.successors = []
        return node

    def copy(self):
        node = CFGNode()
        node.name = self.name
        node.block = self.block.copy()
        node.block_id = self.block_id
        node.addr = node.block.addr
        node.size = node.block.size
        node.is_syscall = self.is_syscall
        node.has_return = self.has_return
        node.function_address = self.function_address
        # Do not copy the neighborhoods, left it to CFG copy.
        node.predecessors = []
        node.successors = []
        return node

    # Modifier
    def appendSuccessor(self, CFGNode):
        if CFGNode not in self.successors:
            self.successors.append(CFGNode)
            CFGNode.predecessors.append(self)
            return self
        return None

    def removeSuccessor(self, CFGNode):
        # Raise exception anyway.
        self.predecessors.remove(CFGNode)
        CFGNode.successors.remove(self)

# Save function related information.
class Function:
    # [Attribute]
    #   addr                    Function address.
    #   name                    Function name.
    #   binary_name             Binary name of this function.
    #   angr_function           Original angr function object.
    #   node_addrs_set          A list of all CFG nodes' address.
    #   nodes                   A dict which maps all addr to corresponding CFG node within this function.
    #   startpoint              Entry CFG node of this function.
    #   endpoints               A list of CFG nodes which can leave this function.
    #   endpoints_with_type     A dict maps ending type to endpoint.
    #   has_return              Whether this function has return.
    #   has_unresolved_calls    Whether this function has unresolved calls.
    #   has_unresolved_jumps    Whether this function has unresolved jumps.
    #   is_plt                  Whether this function is a plt function.
    #   is_syscall              Whether this function is a syscall.
    #   offset                  Function offset.
    #   callees                 A list of function address that may be called by this function.
    #   is_recursive            Whether this function is a recursive function.
    # [Member]
    #   get_node                Get CFG node by addr.

    @staticmethod
    def fromAngrFunction(angr_function: angr.knowledge_plugins.functions.function.Function, angr_cfg: angr.analyses.cfg.cfg_fast.CFGFast):
        # Normalize this function first if not normalized.
        if not angr_function.normalized:
            angr_function.normalize()
        # Normalize this cfg first if not normalized.
        if not angr_cfg.normalized:
            angr_cfg.normalize()

        # Build function object.
        func = Function()
        func.addr = angr_function.addr
        func.name = angr_function.name
        func.binary_name = angr_function.binary_name
        # func.angr_cfg = angr_cfg
        func.angr_function = angr_function
        func.node_addrs_set = angr_function.block_addrs_set.copy()
        func.nodes = {addr:CFGNode.fromAngrCFGNode(angr_cfg.get_any_node(addr)) for addr in func.node_addrs_set}
        func.startpoint = func.getNode(func.addr)
        func.endpoints = [func.getNode(node.addr) for node in angr_function.endpoints]
        func.endpoints_with_type = {type:set([func.getNode(node.addr) for node in nodes]) for type, nodes in angr_function.endpoints_with_type.items() if len(nodes) != 0}
        func.has_return = angr_function.has_return
        func.has_unresolved_calls = angr_function.has_unresolved_calls
        func.has_unresolved_jumps = angr_function.has_unresolved_jumps
        func.is_plt = angr_function.is_plt
        func.is_syscall = angr_function.is_plt
        func.offset = angr_function.offset
        func.callees = set()
        func.is_recursive = False

        # Double check endpoints.
        for endpoint in func.endpoints:
            if 'call' not in endpoint.block.disassembly.insns[-1].mnemonic and not endpoint.has_return:
                func.endpoints.remove(endpoint)

        assert(None != func.startpoint)
        assert(None not in func.endpoints)

        return func

    def rebuildControlFlow(self):
        for node in self.nodes.values():
            angrNode = self.angr_function.get_node(node.addr)
            for successor in angrNode.successors():
                if isinstance(successor, angr.codenode.BlockNode):
                    # Link to a node.
                    assert(successor.addr in self.node_addrs_set)
                    node.appendSuccessor(self.getNode(successor.addr))
                elif isinstance(successor, angr.knowledge_plugins.functions.function.Function):
                    # Link to a function, add it to callees if successor.addr != self.addr.
                    if successor.addr == self.addr:
                        self.is_recursive = True
                    else:
                        self.callees.add(successor.addr)
                else:
                    # May be we should report an error?
                    pass

    # Accessor
    def getNode(self, addr: int):
        if addr not in self.nodes:
            return None
        return self.nodes[addr]

class CFG:
    @staticmethod
    def init(angr_cfg: angr.analyses.cfg.cfg_fast.CFGFast, entrypoint: CFGNode):
        cfg = CFG()
        # Normalize this cfg first if not normalized.
        if not angr_cfg.normalized:
            angr_cfg.normalize()
        # The original CFG we build from.
        cfg.angr_cfg = angr_cfg
        # Entry CFG node.
        cfg.entrypoint = entrypoint
        # Exit CFG nodes.
        cfg.endpoints = []
        # CFGNode map, addr:int -> node:CFGNode.
        # Note that same CFGNode may have multiple instances due to their different contexts.
        cfg.node_map = {entrypoint.addr: [entrypoint]}
        # Unresolved block addresses with indirect jump.
        cfg.unresolved_blocks = []
        return cfg
    
    # TODO: Copy entire CFG, update predecessors and successors for every CFGNode.
    def copy(self):
        cfg = CFG()
        cfg.orig_cfg = self.orig_cfg
        cfg.entrypoint = self.entrypoint.copy()
        cfg.endpoints = [end.copy() for end in self.endpoints]
        cfg.node_map = {addr:node.copy() for addr, node in self.node_map.items()}
        cfg.unresolved_blocks = self.unresolved_blocks.copy()

    # Modifier
    def appendCFGNode(self, node: CFGNode):
        if node.addr not in self.node_map:
            self.node_map[node.addr] = [node]
        elif node not in self.node_map[node.addr]:
            self.node_map[node.addr].append(node)
        return self

    def appendEndpoint(self, node: CFGNode):
        if node not in self.endpoints:
            self.endpoints.append(node)
        return self

    def appendUnresolvedBlock(self, addr: int):
        if addr not in self.unresolved_blocks:
            self.unresolved_blocks.append(addr)
        return self
    
    # Accessor
    def getAnyNode(self, addr: int):
        return self.node_map[addr][0] if addr in self.node_map else None

    def getAllNodes(self, addr: int):
        return self.node_map[addr] if addr in self.node_map else None
