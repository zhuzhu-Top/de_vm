from binaryninja import *
import angr
import re
from pprint import pprint
# from  main import Main
from binaryninja.architecture import Architecture, ArchitectureHook
from binaryninja.enums import *
import os


try:
    from .utils import *
except:
    from utils import *
    from user_il import create_user_func
import json
"""
找到 中间计算过程中所有 相关用到的变量
"""
def find_all_relative_var(jump_var: SSAVariable ,info):
    def_il = jump_var.def_site
    for var in def_il.vars_read:
        if info.get("var_read") is None:
            info["var_read"] = [var]
        else:
            info["var_read"].append(var)
        find_all_relative_var(var,info)
def get_jump_target(bv: BinaryView,jump_var,info):
    if not isinstance(jump_var, binaryninja.mediumlevelil.SSAVariable):
        print("jump_var must be an SSAVariable")
        raise Exception("输入参数不是变量 mlil ssa 变量")
    def_il = jump_var.def_site
    var2value = {
        "true": {

        },
        'false': {

        }
    }
    for var in def_il.vars_read:
        var_text = f"{var.name}#{var.version}"
        # binaryninja.mediumlevelil.MediumLevelILVarPhi
        var_type = def_il.get_ssa_var_possible_values(var).type
        if var_type == RegisterValueType.UndeterminedValue:
            # var_value = get_jump_target(bv,var,info)
            # if var_value is None:
            raise Exception("忘记了")
            # var2value[var_text] = var_value
            # info[var_text] = var_value
        elif var_type == RegisterValueType.InSetOfValues or RegisterValueType.ConstantValue:
            # 如果变量的定义里面 没有继续读取变量 这种才是真的常量
            if len(var.def_site.vars_read) == 0:
                if var == info["true_branch_var"]:
                    var2value['true'][var_text] = def_il.get_ssa_var_possible_values(var).value
                elif var == info["false_branch_var"]:
                    var2value['false'][var_text] = def_il.get_ssa_var_possible_values(var).value

                else:
                    raise f"error {var}"
            else:
                var_value = get_jump_target(bv,var,info)
                var2value = var_value

                info[var_text] = var_value
        else:
            raise Exception("Unexpected variable type")
    if def_il.instr.operation == MediumLevelILOperation.MLIL_VAR_PHI:
        # ['x11#3', ' = ', 'ϕ', '(', 'x11#1', ', ', 'x11#2', ')']
        # Phi 节点返回所有的值
        true_branch_var = info["true_branch_var"]
        true_var_text = f"{true_branch_var.name}#{true_branch_var.version}"
        false_branch_var = info["false_branch_var"]
        false_var_text = f"{false_branch_var.name}#{false_branch_var.version}"

        _ret = {
            "true": {
                def_il.tokens[0].text: var2value['true'][true_var_text]
            },
            "false":  {
                def_il.tokens[0].text: var2value['false'][false_var_text]
            },
        }
        return _ret
    elif def_il.instr.operation == MediumLevelILOperation.MLIL_SET_VAR_SSA:
        tmp_tokens = [i.text for i in def_il.tokens]
        tmp_tokens = ''.join(tmp_tokens)
        true_expr_list = []
        false_expr_list = []
        raw_expr = ""
        if isinstance(def_il.src,binaryninja.mediumlevelil.MediumLevelILLoadSsa):
            # ['x13#1', ' = ', '[', '0x1ddc80', ' + ', 'x11#3', ']', '.q', ' @ ', 'mem#0']
            search_ret = re.search("=(.*?)@",tmp_tokens)
            if search_ret is None:
                print(f" {tmp_tokens} not found in {def_il} ")
                raise Exception(f" {tmp_tokens} not found in {def_il} ")
            raw_expr = search_ret.group(1)
        else:
            raw_expr = tmp_tokens[tmp_tokens.find("=")+1:]
        # if info.get("expr") is None:
        #     info["expr"] = [raw_expr]
        # else:
        #     info["expr"].append(raw_expr)
        _ret = {
            "true": {
            },
            "false":  {
            },
        }
        for tag in var2value:
            val_name = list(var2value[tag].keys())[0]
            value = var2value[tag][val_name]
            # value
            if tag == 'true':
                _ret["true"][def_il.tokens[0].text] = (
                    bv.parse_expression(raw_expr.replace(val_name, "0x{:X}".format(value))))
            else:
                _ret["false"][def_il.tokens[0].text] = (
                    bv.parse_expression(raw_expr.replace(val_name, "0x{:X}".format(value))))
        return _ret

    else:
        print("未处理的情况")
        raise Exception("未处理的情况")

"""
便利所有读取的变量，找到两个变量的上一个块是同一个 而且是 if else 的跳转
"""
def get_cmp_info(info):
    for var in info["var_read"]:
        var: binaryninja.mediumlevelil.SSAVariable
        var_block = var.def_site.ssa_form.il_basic_block
        # [<TrueBranch: aarch64@0x10>]
        if var_block.incoming_edges.__len__() != 1:
            continue
        # 找到两个变量的上一个block是相同的
        for in_var in info["var_read"]:
            in_var: binaryninja.mediumlevelil.SSAVariable
            in_var_block = in_var.def_site.ssa_form.il_basic_block
            if var == in_var:
                print(var,in_var)
                continue
            # [<FalseBranch: aarch64@0x12>]
            if in_var_block.incoming_edges.__len__() != 1:
                continue
            if var.def_site.vars_read.__len__() !=0:
                continue
            # 这两个变量的定义 block 应该不在一个 block
            if in_var.def_site.il_basic_block == var.def_site.il_basic_block:
                continue
            if var_block.incoming_edges[0].source == in_var_block.incoming_edges[0].source :
                same_block = var_block.incoming_edges[0].source
                if_il : binaryninja.mediumlevelil.MediumLevelILIf = same_block[-1]
                if if_il.operation == MediumLevelILOperation.MLIL_IF:
                    print(f"true -> {if_il.operands[1]} false -> {if_il.operands[2]}")
                    info["true_branch"] =if_il.operands[1]
                    info["false_branch"] =if_il.operands[2]
                    # 最顶层的
                    info["true_branch_var"] = var if var_block.start == info["true_branch"] else in_var
                    info["false_branch_var"] = var if var_block.start == info["false_branch"] else in_var
                    info["cmp"] = if_il
                    return True
    return False
def patch_llil_ssa(func :binaryninja.function.Function,cmp_expr,true_addr,false_addr,jump_to_il : lowlevelil.LowLevelILInstruction):
    llil = func.llil
    true_il = func.get_llil_at(true_addr)
    if true_il == None:
        return False
    true_inst_id =true_il.instr_index
    false_il = func.get_llil_at(false_addr)
    if false_il == None:
        return False
    false_inst_id = func.get_llil_at(false_addr).instr_index
    true_label = LowLevelILLabel()
    true_label.operand = true_inst_id
    false_label = LowLevelILLabel()
    false_label.operand = false_inst_id

    # 确保生成指令的地址为当前 br reg的位置
    llil.set_current_address(jump_to_il.address)
    new_if_expr = llil.if_expr(cmp_expr,true_label,false_label)
    llil.replace_expr(jump_to_il.expr_index,new_if_expr)

    return True


def print_jump_target(bv: BinaryView):
    func = bv.get_functions_containing(0x9cc7c)[0]

    llil_ssa = func.llil.ssa_form
    jump_to_list = find_operation(llil_ssa,LowLevelILOperation.LLIL_JUMP_TO)
    find_all_flag_def_info(func.llil)

    out= {

    }
    procedure_addr = set()
    for jump_to in jump_to_list:
        pp_print(f"jump to {hex(jump_to.address)} {str(jump_to)}")
        jump_to_mlil = jump_to.mlil.ssa_form
        br_var = jump_to_mlil.vars_read[0]
        pp_print(f"br var  {str(br_var)}")

        info = {}
        find_all_relative_var(br_var, info)
        get_cmp_info(info)
        jump_target = get_jump_target(bv, br_var, info)
        # 计算跳转变量的过程中的变量的地址都需要nop

        for used_var in info["var_read"]:
            used_var: binaryninja.mediumlevelil.SSAVariable
            use_sites = used_var.use_sites
            for use in use_sites:
                # 通过运算再给自己复制到变量 不能认为是计算过程中的变量,有的变量的定义有几行il组成
                #   38 @ 0009cc4c  w12 = &__elf_rela_table[0x95].r_addend+1
                #   39 @ 0009cc50  w12 = w12 & 0xffff
                #   40 @ 0009cc50  w12 = w12 | 0xa31c0000


                if isinstance(use.src,list):# 自己经过操作再给自己赋值,源操作数一定至少有两个
                    _var = use.dest.var
                    _flag = False
                    for _src in use.src:
                        if _src.var == _var:
                            _flag = True
                            break
                    if _flag:
                        continue

                procedure_addr.add(use.address)


        out[jump_to.address] = {
            "cmp_addr": info['cmp'].address,
            "true_addr": jump_target['true'][list(jump_target['true'])[0]] ,
            "false_addr": jump_target['false'][list(jump_target['false'])[0]] ,
        }
        # 比较 的过程也需要nop 后面会直接把比较的条件放到 后面去 (br reg 改成 if(cmp) true else false)
        procedure_addr.add(info['cmp'].address)
    out["procedure_addr"] =[i for i in  list(procedure_addr)]


    # 收集所有 if, 不能是上面出现的nop( if的cmp和跳转都 需要nop)的地址 ,这些地址会设置 跳转的索引,去跳转到下一个真实块
    if_list = find_operation(func.llil, LowLevelILOperation.LLIL_IF)
    if_fillter = []
    for if_il in if_list:
        if if_il.address not in out["procedure_addr"]:
            if_fillter.append(if_il)

    reg2values ={

    }

    # 拿到所有固定的常量
    for blocks in func.llil:
        # 最后一个return 的 block 里面会给当前 函数需要恢复的寄存器恢复,所以不能遍历这个
        if blocks[-1].operation == LowLevelILOperation.LLIL_RET:
            continue
        for il in blocks:
            # 需要not的地址,不需要记录寄存器的值
            if il.address in out["procedure_addr"]:
                continue

            for operand in il.operands:
                if isinstance(operand, LowLevelILReg):
                    reg_value = get_reg_const_value_after(il,operand.src)
                    if reg_value is not None:
                        if reg2values.get(il.address) == None:
                            reg2values[il.address] = {
                                operand.src.name: reg_value.value,
                            }
                        else:
                            reg2values[il.address][operand.src.name] = reg_value.value
                    continue

                if not isinstance(operand,LowLevelILInstruction):
                    continue
                for inner_operands in operand.operands:
                    if not isinstance(inner_operands,LowLevelILReg):
                        continue
                    reg_value = get_reg_const_value_after(inner_operands,inner_operands.src)
                    if reg_value is None:
                        continue

                    if reg2values.get(il.address) == None:
                        reg2values[il.address]={
                            inner_operands.src.name:reg_value.value,
                        }
                    else:
                        reg2values[il.address][inner_operands.src.name] = reg_value.value

    out["reg2values"] = reg2values
    # pp_print(out)
    current_work_dir = os.path.dirname(__file__)
    file_path =current_work_dir+"\\data.json"
    with open(file_path,"w") as f:
        f.write(json.dumps(out))

    # func.llil.generate_ssa_form()
# workflows.functionWorkflow


# setting = Settings()
# for k in setting.keys():
#     print(k)
# project = angr.Project('D:/TMP/libtprt.so', load_options={"auto_load_libs": False})

# Main(bv, project)



if __name__ == '__main__':

    bv = load(r"D:\TMP\libtprt.so.bndb",options = {
        "workflows.functionWorkflow":"PythonLogWarnWorkflow",
    })
    create_user_func(bv)
    print_jump_target(bv)