import os

from binaryninja import *
from pprint import pprint
import json
from .header_less import patch_llil_ssa,find_all_relative_var
from .utils import *



def patch_to_nop(func :binaryninja.function.Function,addr):
    llil = func.llil
    # cinc 这种类似的指令一个地址会生成多条il,全部都需要nop

    # il = func.get_llil_at(addr)
    # if il is None:
    #     return
    # if il.operation == LowLevelILOperation.LLIL_NOP:
    #     return
    # llil.set_current_address(addr)
    # llil.replace_expr(il.expr_index, llil.nop())
    #
    llil.set_current_address(addr)
    ils = func.get_llils_at(addr)
    for il in ils:
        if il is None:
            return
        if il.operation == LowLevelILOperation.LLIL_NOP:
            return
        nop_expr = llil.nop()
        llil.replace_expr(il.expr_index,nop_expr)
        new_nop = llil.get_expr(nop_expr)
        pp_print(f"nop :[{len(ils)}] {hex(addr)} {str(il)} => {str(new_nop)}")

def backup_cmp_info(func :binaryninja.function.Function,addr):
    il: LowLevelILInstruction = func.get_llil_at(addr)
    if il.operation == LowLevelILOperation.LLIL_IF:
        # if 比较的内容
        cmp_il = il.operands[0]
        binaryninja.lowlevelil.ILFlag
        if cmp_il.operation == LowLevelILOperation.LLIL_FLAG:
            cond_addr = cmp_il


"""
第一阶段 根据 分析数据 恢复控制流
"""
def recover_branch(func :binaryninja.function.Function,procedure_addrs,jumps):

    llil = func.llil

    flag_def_info = find_all_flag_def_info(llil)

    for jump_item in jumps.items():

        # 找到下一个有效的地址
        def find_next_effective_addr(addr):
            while True:
                if addr in procedure_addrs:
                    patch_to_nop(func, addr)
                    procedure_addrs.remove(addr)
                    addr +=4
                else:
                    return addr

        key = jump_item[0]
        cmp_addr=  jump_item[1]["cmp_addr"]
        true_addr=  jump_item[1]["true_addr"]
        false_addr=  jump_item[1]["false_addr"]
        jump_to = func.get_llil_at(int(key))

        # 跳过中间计算跳转变量的过程
        # true_addr = find_next_effective_addr(true_addr)
        # false_addr = find_next_effective_addr(false_addr)
        find_next_effective_addr(true_addr)
        find_next_effective_addr(false_addr)
        cmp_il = func.get_llil_at(cmp_addr)
        suc = False
        llil.set_current_address(jump_to.address)
        if LowLevelILOperation.LLIL_FLAG == cmp_il.operands[0].operation:
            # 比较内容是 flag
            #   48 @ 0009cc5c  if (cond:0) then 49 else 51
            # >>> func.get_llil_at(0x9cc5c).operands[0].operands
            # [<ILFlag: cond:0>]
            flag_name = cmp_il.operands[0].operands[0].name
            flag_info = flag_def_info[flag_name]
            raw_operands = flag_info["raw_operands"]
            new_cmp_il = llil.expr(
                flag_info["operation"],
                raw_operands[0],
                raw_operands[1],
                raw_operands[2],
                raw_operands[3],
                flag_info["size"],
                None
            )
            suc = patch_llil_ssa(func, new_cmp_il, true_addr, false_addr, jump_to)

        #  43 @ 0009cc58  if (w12 s< w22) then 44 else 46
        if isinstance(cmp_il.operands[0], lowlevelil.LowLevelILComparisonBase):
            # 构造新的比较条件 直接用现有的比较条件里面的内容

            new_cmp_il = llil.expr(
                cmp_il.operands[0].operation,
                cmp_il.operands[0].raw_operands[0],
                cmp_il.operands[0].raw_operands[1],
                cmp_il.operands[0].raw_operands[2],
                cmp_il.operands[0].raw_operands[3],
                cmp_il.operands[0].size,
                None
            )
            suc = patch_llil_ssa(func, new_cmp_il, true_addr, false_addr, jump_to)
        if not suc:
            return

        pp_print(f"jump : {hex(jump_to.address)} ,cmp[ {hex(cmp_addr)} ],true_addr[ {hex(true_addr)} ],false_addr[ {hex(false_addr)} ]")

    # 上面nop的是用于计算下一次跳转 目的地址的过程
    # 接下来nop分发的那些代码

    for procedure_addr in procedure_addrs:

        patch_to_nop(func,procedure_addr)

    # os.remove(file_name)
    llil.finalize()
    llil.generate_ssa_form()
"""
找到 跳转的 变量
"""
def find_primary_var(llil : lowlevelil.LowLevelILFunction):
    if_list = find_operation(llil,LowLevelILOperation.LLIL_IF)
    info = {

    }
    # 找到if中出现次数最多的变量就是 负责跳转的变量
    for if_il in if_list:
        cmp_il = if_il.operands[0]
        # if cmp_il.operation == LowLevelILOperation.LLIL_CMP_E:
             #         <LowLevelILCmpE: w12 == w15>
        left = cmp_il.operands[0].src
        right = cmp_il.operands[0].src
        info[left]  = info.get(left)+1  if info.get(left) is not None else 0
        info[right] = info.get(right)+1 if info.get(right) is not None else 0

    primary_reg = None
    max_count = 0
    for reg,count in info.items():
        if count > max_count:
            max_count = count
            primary_reg = reg

    return primary_reg,if_list
"""
第二阶段 恢复代码的 控制流
"""
def recover_blcok_flow(func :binaryninja.function.Function,reg2values: dict):
    llil = func.llil
    llil_ssa=  llil.ssa_form
    llil_ssa.ssa_regs
    llil_ssa.get_ssa_reg_definition
    primary_reg,if_list = find_primary_var(llil)

    number2inst_id = {

    }
    patch_data = {

    }
    for if_il in if_list:
        if_il : lowlevelil.LowLevelILIf
        cmp_il = if_il.operands[0]
        #   if (w12 == w23) 这种 对应的就是真实块
        if cmp_il.operation == LowLevelILOperation.LLIL_CMP_E:
            cmp_right: LowLevelILReg = cmp_il.right
            if cmp_right.value.type != RegisterValueType.ConstantValue:
                continue
            number2inst_id[cmp_right.value.value] = if_il.true
        else:
            # 不是等于的话 就是 从真实块跳到 下一个真实块的
            # true_il = llil[if_il.true]
            def set_patch_data(_il,true):
                # <LowLevelILSetReg: w12 = w23>
                if (_il.operation != LowLevelILOperation.LLIL_SET_REG
                        or not isinstance(_il.dest,binaryninja.lowlevelil.ILRegister)
                        or _il.dest.name != primary_reg.name):
                    return
                if not isinstance(_il.src, LowLevelILReg):
                    return
                values = reg2values.get(str(_il.address))
                if values is None or values.get(_il.src.src.name) is None:
                    return
                target_block_number = values.get(_il.src.src.name)
                if true:
                    patch_data[if_il] = {
                        "true": target_block_number
                    }
                else:
                    patch_data[if_il]["false"] = target_block_number

            set_patch_data(llil[if_il.true],True)
            set_patch_data(llil[if_il.false],False)
    """
    {<LowLevelILIf: if (x10 u< x9) then 90 else 92>: 
            {
            'true': 1104611000,
            'false': 1482094495
            }}
    """
    for if_il,true_false in patch_data.items():
        if_il: lowlevelil.LowLevelILIf
        if number2inst_id.get(true_false["true"]) is None or number2inst_id.get(true_false["false"]) is None:
            continue
        llil.set_current_address(if_il.address)
        llil.replace_expr(if_il.expr_index,
                          llil.expr(if_il.operation,
                                    if_il.raw_operands[0], # cmp 保留比较条件
                                    number2inst_id.get(true_false["true"]), # true
                                    number2inst_id.get(true_false["false"]), # false
                                    if_il.raw_operands[3],
                                    ))
    llil.finalize()
    llil.generate_ssa_form()
binaryninja.architecture.CoreArchitecture
def cus_workflow(analysisContext : AnalysisContext):
    # 因为只有一个函数的反混淆,想看原始的代码的样子就不能改il
    return
    # 连接pycharm 调试器 不用就注释掉
    # try:
    #     import pydevd_pycharm
    #     pydevd_pycharm.settrace('localhost', port=9999, stdoutToServer=True, stderrToServer=True, suspend=False)
    # except:
    #     pass

    func = analysisContext.function
    if func.start != 0x9cbe0:
        return
    is_enbale_custom_workflow = Settings().get_bool("zhuzhu.workFlow")
    if not is_enbale_custom_workflow or is_enbale_custom_workflow==None:
        return

    llil = func.llil

    current_work_dir = os.path.dirname(__file__)
    file_path =current_work_dir+"\\data.json"
    if not os.path.isfile(file_path):
        return
    file = open(file_path, "r")
    jumps= json.loads(file.read())
    file.close()


    procedure_addrs = jumps["procedure_addr"]
    jumps.pop("procedure_addr")

    reg2values = jumps["reg2values"]
    jumps.pop("reg2values")

    recover_branch(func,procedure_addrs,jumps)


    # recover_blcok_flow(func,reg2values)



    # file_name = r"C:\Users\zhuzhu\AppData\Roaming\Binary Ninja\plugins\deobf\dy_code.py"
    # global_namespace = globals()
    # local_namespace = locals()
    # with open(file_name, "r") as f:
    #     try:
    #         exec(compile(f.read(), file_name, "exec"), global_namespace, local_namespace)
    #     except BaseException as e:
    #         log_error(traceback.format_exc())

