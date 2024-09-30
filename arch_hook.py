from binaryninja.architecture import Architecture, ArchitectureHook
from capstone import *
from binaryninja import *
import binaryninja._binaryninjacore as core
md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
md.detail = True






class Arm64RetHook(ArchitectureHook):

    def __init__(self, base_arch):
        super(Arm64RetHook, self).__init__(base_arch)

    # def get_instruction_info(self, data, addr):
    #     info = super(Arm64RetHook, self).get_instruction_info(data, addr)
    #     branches = info.branches
    #     # So dataflow doesn't stop at a return
    #     for b in branches:
    #         if b.type == BranchType.FunctionReturn:
    #            b.type = BranchType.UnresolvedBranch
    #     info.branches = branches
    #     return info

    def get_instruction_low_level_il(self, data, addr, il: LowLevelILFunction):
        insn = md.disasm(data, addr)
        il.handle
        if addr == 0x9cc58:
            core.BNLowLevelILAddExprWithLocation(il.handle,LowLevelILOperation.LLIL_SET_REG)
            # nzcv_reg = self.get_reg_index("nzcv")
            il
            # il.set_flag()
            il.append(il.set_reg(4, "nzcv",il.reg(4,"nzcv")))
            # il.append(il.set_reg(16,"w1",il.const(16,2)))
            # return 4

        return super(Arm64RetHook, self).get_instruction_low_level_il(data, addr, il)
