import capstone
from binaryninja import *
from capstone.arm64 import *
from pprint import pprint
def pp_print(str):
    pprint(str)

def get_targte_reg_name(bv,cs,address):
    # address = 0x9cc7c
    inst_bytes = bv.read(address, bv.get_instruction_length(address))
    for inst in cs.disasm(inst_bytes, address):
        inst: capstone.CsInsn = inst
        for operand in inst.operands:
            operand: capstone.arm64.Arm64Op = operand
            return inst.reg_name(operand.value.reg)


def find_operation(llil :LowLevelILFunction,llil_operation: LowLevelILOperation) -> List[Optional[LowLevelILInstruction]]:
    def find_(llil_inst: LowLevelILInstruction):
        if llil_inst.operation == llil_operation:
            return llil_inst
    return list(llil.traverse(find_))


# 找到所有设置 flag的地方 并返回 operation(怎么比较的) raw_operands 比较的寄存器
def find_all_flag_def_info(llil :LowLevelILFunction):
    fag_defs_il = find_operation(llil,LowLevelILOperation.LLIL_SET_FLAG)
    info = {

    }
    for flag in llil.flags:
        for index,il in enumerate(fag_defs_il):
            il : LowLevelILSetFlag
            if il.operands[0].name == flag.name:
                info[flag.name] = {
                    "operation": il.operands[1].operation,
                    "raw_operands": il.operands[1].raw_operands,
                    "size": il.operands[1].size
                }
                fag_defs_il.pop(index)
                break
    return info

# 只获取只有一个值的寄存器的值
def get_reg_const_value_after(il,reg):
    reg_value = il.get_possible_reg_values_after(reg)
    # 只需要 只可能是一个值的
    # 多个值的是 InSetOfValues 未知的是 UndeterminedValue
    if not reg_value.type == RegisterValueType.ConstantValue:
        return None
    return reg_value

# 判断是否是操作自己 sp = sp - 0x70
#   x20 = x20 + 0xc80
def is_operate_self(il:LowLevelILInstruction):

    if not hasattr(il,"src") or not hasattr(il,"dest"):
        return False


def get_llil_var_def_tree(func,llil):
    func_llil_ssa = func.llil.ssa_form
    if isinstance(llil, LowLevelILBinaryBase):
        left = llil.left
        right = llil.right
        _left = get_llil_var_def_tree(func,left)
        _right = get_llil_var_def_tree(func,right)
        return {
            "il": llil,
            "left_child": _left,
            "right_child": _right,
            "addr": llil.address,
        }
    elif isinstance(llil, LowLevelILConst):
        return {
            "il": llil,
            "value": llil.value.value,
            "addr": llil.address,
        }
    elif isinstance(llil, LowLevelILRegSsaPartial):
        operands = llil.operands
        register = operands[0]
        set_reg_ssa_il = func_llil_ssa.get_ssa_reg_definition(register)
        return get_llil_var_def_tree(func,set_reg_ssa_il)
    elif isinstance(llil, LowLevelILLowPart):
        return get_llil_var_def_tree(func,llil.src)
    elif isinstance(llil, LowLevelILZx) or isinstance(llil, LowLevelILSx):
        # <LowLevelILZx: zx.q(x9#6.w9)> 直接返回出去
        return get_llil_var_def_tree(func,llil.src)
    elif isinstance(llil, LowLevelILSetRegSsa):
        _ret = get_llil_var_def_tree(func,llil.src)
        return {
            "il": llil,
            "child": _ret,
            "addr": llil.address,
        }
        # ret[f"{llil.src.reg.name}#{llil.src.version}"] = _ret
    elif isinstance(llil, LowLevelILLoadSsa):
        _ret = get_llil_var_def_tree(func,llil.src)
        return {
            "il": llil,
            "child": _ret,
            "addr": llil.address,
        }
    elif isinstance(llil, LowLevelILRegSsa):
        set_reg_ssa_il = func_llil_ssa.get_ssa_reg_definition(llil.src)
        # _ret = get_llil_var_def_tree(set_reg_ssa_il)
        return get_llil_var_def_tree(func,set_reg_ssa_il)
        # ret[f"{llil.src.reg.name}#{llil.src.version}"] = _ret



def to_signed(value, bits):
    if value & (1 << (bits - 1)):
        return value - (1 << bits)
    return value