from angr import SimulationManager
import angr
from queue import Queue
from angr.procedures.procedure_dict import SIM_PROCEDURES
from pyvex.lifting.util import JumpKind
import pyvex
import json
from binaryninja import *

from graphviz_tools import generate_dot_for_llil_var

project = angr.Project(r'D:\window\AndroidRe\ttEncrypt\libEncryptor.so', load_options={"auto_load_libs": False})
bv = load(r"D:\window\AndroidRe\ttEncrypt\libEncryptor.so.bndb")
func = bv.get_function_at(0x2c18)
def get_dispatcher_state(function):
    state = project.factory.call_state(addr=function)
    # Ignore function calls
    # https://github.com/angr/angr/issues/723
    # state.options.add(angr.options.CALLLESS)
    simgr = project.factory.simulation_manager(state)
    # state.options.add(angr.options.TRACK_OP_ACTIONS)
    # state.options.add(angr.options.TRACK_ACTION_HISTORY)
    # state.options.add(angr.options.TRACK_REGISTER_ACTIONS)
    # 记录中间变量
    # state.options.add(angr.options.TRACK_TMP_ACTIONS)
    simgr.explore(find=dispatcher_addr)
    # simgr.explore(find=start_address+ 0x3c1c)
    if simgr.found:
        _init = simgr.found[0]
        return _init.copy()
    else:
        raise Exception("未找到分发器")

def find_successors(state_value, dispatcher,debug = False) -> angr.SimState:
    state = dispatcher_state.copy()
    # 记录 寄存器操作
    state.options.add(angr.options.TRACK_OP_ACTIONS)
    state.options.add(angr.options.TRACK_ACTION_HISTORY)
    state.options.add(angr.options.TRACK_REGISTER_ACTIONS)
    # 记录中间变量
    state.options.add(angr.options.TRACK_TMP_ACTIONS)
    # state.options.add(angr.options.TRACK_JMP_ACTIONS)
    setattr(state.regs,state_register_name,state.solver.BVV(state_value, 64))
    solver = state.solver
    for vreg_index in range(0,32):

        state.mem[state.regs.x19 - 0x138 + (vreg_index <<3)].uint64_t = solver.BVS(f"vreg{vreg_index}",64)

    simgr = project.factory.simulation_manager(state)

    # 必须先step一下 不然就直接结束了
    new_sm = simgr.step()
    back_state = new_sm.active[0]

    if debug:
        print(hex(state.addr)," -> ",hex(back_state.addr))
        while True:
            simgr.step()
            find_state = simgr.active[0]
            print(hex(simgr.active[0].addr))
            pass
    new_sm.explore(find=dispatcher)
    if new_sm.found:
        # [可能1] 直接跳转到下一个块
        # [可能2] 这个block下面有两个后继可以选择
        # 所以 eval_upto 第二个参数是 2
        found_state = new_sm.found[0]

        return found_state
    else:
        raise Exception("未处理异常")
        # 不跳转到分发器 可能是 ret
        def find_ret(_state: angr.SimState):
            return _state.history.jumpkind == JumpKind.Ret

        _ret_sm = project.factory.simulation_manager(back_state)
        _ret_sm.explore(find=find_ret)
        if _ret_sm.found:
            found_state = _ret_sm.found[0]
            return found_state, []
        else:
            raise Exception("未处理异常,可能不是ret的情况")
    # while True:
    #     print(f"eax: {simgr.active[0].regs.x12}")
    #     print(f"Stepping: {simgr.active} ...")
    #     simgr.step()
    #     new_state = simgr.active[0]
    #     if simgr.successors(new_state).is_empty:  # 为空就是 ret 的 block
    #         return state,[]
    #     if new_state.addr == dispatcher:
    #         solutions = new_state.solver.eval_upto(new_state.regs.x12, 2)
    #         return state, solutions
    #     state = new_state

def split_jump2block(jump_sources,jump_targets):
    jump_sources= [i-start_address for i in sorted(jump_sources,reverse=True)]
    jump_targets= [i-start_address for i in sorted(jump_targets,reverse=True)]
    blocks = {}

    for indx,jump_source in enumerate(jump_sources):
        # print(hex(jump_source)," -> ",hex(jump_targets[indx+1]))
        block_range = (jump_targets[indx+1],jump_source)
        if block_range[0] <= dispatcher_addr-start_address and block_range[1]>= dispatcher_addr-start_address:
            break

        # range函数是不包含右边的,所以要 +4   step = -4
        block_addrs = [i for i in range(block_range[0],block_range[1]+4,4)]
        blocks[block_range] =block_addrs
    return blocks

def get_opcode_llil(blocks):

    addr2llil = {}
    for block_range in sorted(blocks.keys(),reverse=False):
        blokc_start = block_range[0]
        blokc_end = block_range[1]
        addrs = blocks[block_range]
        collected_expr = []
        for inst_addr in addrs:
            llil = func.get_llil_at(inst_addr)
            addr2llil[hex(inst_addr)] = str(llil)
            if collected_expr.count(llil.expr_index) == 0:

                collected_expr.append(llil.expr_index)

        # print(f"{hex(blokc_start)} - {hex(blokc_end)} ", f"{[hex(i) for i in addrs]}")
    return addr2llil

def collect_action_info(found_state):
    addrs = []
    index = 0
    addr2action = {

    }
    for action in found_state.history.actions:
        real_addr = action.ins_addr - start_address

        if index != 0 and addrs[index - 1] == real_addr:
            addr2action[real_addr].append(action)
            continue
        addrs.append(real_addr)
        addr2action[real_addr] = []
        addr2action[real_addr].append(action)
        index += 1

    return addrs,addr2action
def get_opcode_llil(addr_detail,print_result = False):
    llils = {

    }

    index =0
    for addr, actions in addr2action.items():
        llil = func.get_llil_at(addr)
        # cinc 这种 条件的语句也会变成 if,因为 if 后面走的代码也是在 if的地址上的,也需要记录上
        if llil.operation is LowLevelILOperation.LLIL_IF:
            true_inst_id = llil.operands[1]
            false_inst_id = llil.operands[2]
            true_llil = func.llil[true_inst_id]
            false_llil = func.llil[false_inst_id]
            if true_llil.address == false_llil.address == llil.address:
                llils[addr] = {
                    "cmp": llil,
                    "true":true_llil,
                    "false":false_llil
                }
                continue

        if index!=0 and llil[index-1] == llil:
            continue
        llils[addr] = llil
    # for addr,actions in addr_detail.items():
    #     print(hex(addr),actions)
    if print_result:
        for addr,llil in llils.items():
            print(hex(addr),llil)
    return llils
def from_action_get_value(addr2action,hlil : binaryninja.HighLevelILInstruction):
    actions = addr2action[hlil.address]
    actions.reverse()
    reg_name = hlil.llil.dest.reg.name
    for action in actions:
        if isinstance(action, angr.state_plugins.SimActionData):
            if action.type == action.REG and action.WRITE and action.storage == reg_name:
                # reg/write
                bv = action.data.ast
                actions.reverse()
                return bv.concrete_value,bv.length
    raise Exception("没有在action里面找到寄存器的值")

# LLILOperation2Str={
#
#     LowLevelILAdd:  "Add",
#     LowLevelILSub:  "Sub",
#     LowLevelILAnd:  "And",
#     LowLevelILOr:   "Or",
#     LowLevelILXor:  "Xor",
# }
"""
from enum import Enum
class RegisterType(Enum):
    VREG   = 1<<0  #来源于 虚拟寄存器
    OpCode = 1<<1  #来源于 opcode算出来的立即数
    UNKONW = 1<<3
   # 实现自定义的序列化方法
    def __json__(self):
        return self.name  # 或者返回 self.value
def get_llil_var_def_tree(llil):
    func_llil_ssa = func.llil.ssa_form

    if isinstance(llil,LowLevelILBinaryBase):
        left = llil.left
        right = llil.right
        _left = get_llil_var_def_tree(left)
        _right = get_llil_var_def_tree(right)
        return {
            "op": llil.operation.name,
            "left": _left,
            "right": _right,
            "addr":llil.address,
        }
    elif isinstance(llil,LowLevelILConst):
        return llil.value.value


    elif isinstance(llil,LowLevelILRegSsaPartial):
        operands = llil.operands
        register = operands[0]
        set_reg_ssa_il = func_llil_ssa.get_ssa_reg_definition(register)
        return get_llil_var_def_tree(set_reg_ssa_il)
    elif isinstance(llil,LowLevelILLowPart):
        return get_llil_var_def_tree(llil.src)
    elif isinstance(llil,LowLevelILZx) or isinstance(llil,LowLevelILSx):
        # <LowLevelILZx: zx.q(x9#6.w9)> 直接返回出去
        return get_llil_var_def_tree(llil.src)

    elif isinstance(llil,LowLevelILSetRegSsa):
        # 如果是给 x12赋值,也算是
        # ssa form 里面操作的 全部都是完成的寄存器 只有 no_ssa_forn 才是半个
        if llil.non_ssa_form.dest.name == VmOpCodeRegister:
            return {"reg_name":VmOpCodeRegister}
        _ret = get_llil_var_def_tree(llil.src)
        return {
            "op": llil.operation.name,
            "set_reg" : _ret,
            "reg_name": f"{llil.dest.reg.name}#{llil.dest.version}",
            "addr": llil.address,
        }
        # ret[f"{llil.src.reg.name}#{llil.src.version}"] = _ret
    elif isinstance(llil,LowLevelILLoadSsa):
        _ret = get_llil_var_def_tree(llil.src)
        return {
            "op": llil.operation.name,
            "mem_load" : _ret,
            "addr":llil.address,
        }
    elif isinstance(llil,LowLevelILRegSsa):
        # 对于直接是寄存器的 需要继续遍历找到定义寄存器的位置
        if llil.src.reg.name == VmContextRegister:
            return {"reg_name":VmOpCodeRegister}
        set_reg_ssa_il = func_llil_ssa.get_ssa_reg_definition(llil.src)
        # _ret = get_llil_var_def_tree(set_reg_ssa_il)
        return get_llil_var_def_tree(set_reg_ssa_il)
        # ret[f"{llil.src.reg.name}#{llil.src.version}"] = _ret
"""



VmCodes = [

]
VmContextRegister = "x19"
VmOpCodeRegister = "w12"
# state_value => real basic block state
states = {}

if __name__ == '__main__':

    start_address = project.loader.min_addr

    # 负责跳转的寄存器
    state_register_name = "w12"
    # 分发器的地址(必须是第一行)
    dispatcher_addr = start_address+0x00002ccc
    # 根据函数起始地址获取分发器的初始 state
    dispatcher_state = get_dispatcher_state(start_address + 0x2ac4)

    print(f"Dispatcher state: {dispatcher_state}")
    initial_state = dispatcher_state.solver.eval_one(dispatcher_state.regs.get(state_register_name))
    print(f"Initial {state_register_name}: {hex(initial_state)}")

    irsb = project.factory.block(start_address+0x3380)
    collected_info = {

    }

    vm_pc = 0xb090
    vm_index = 0
    while True:
        opcode = bv.read_int(vm_pc,4,sign=False,endian=Endianness.LittleEndian)
        print(f"index : {vm_index} vm_pc: {hex(vm_pc)} opcode: {hex(opcode)}")
    # for index,code in enumerate(VmCodes):

        # print(index, hex(code))
        found_state = find_successors(opcode,start_address+0x00003a78,False)
        irsb: pyvex.block.IRSB = found_state.scratch.irsb
        solver = found_state.solver
        # found_state.solver.eval_to_ast()
        # angr.SimActionExit
        # found_state.history.recent_events
        # print(list(found_state.history.actions))


        # jump_targets 会一直到 ip + 4 的位置 所以需要多往前一个才是最后一个 block 的开始
        jump_targets = [i.v-start_address for i in found_state.history.jump_targets]
        jump_sources = [i-start_address for i in found_state.history.jump_sources]

        # primary_block_start = jump_targets[-2]
        # primary_block_end = jump_sources[-1]
        # blocks = split_jump2block(jump_sources,jump_targets)

        addrs,addr2action = collect_action_info(found_state)
        addr2llil = get_opcode_llil(addr2action)

        collected_info[f"{vm_index}_{code}"] = {
            "addr2action": addr2action,
            "addr2llil": addr2llil,
        }
        # for addr,llil in addr2llil.items():
        #     actions = addr2action[addr]
        #     print(hex(addr),llil)
        # for addr,actions in addr2action.items():
        #     for action in actions:
        #         print(hex(addr),action)
        # primary_llil.hlil.dest.src.right.left.src.src
        # 为了能够得到跳板函数的计算过程 必须先进行部分还原
        #  228 @ 00003054  [x11 + (zx.q(w8) << 3)].q = x9
        #  229 @ 00003058  goto 76 @ 0x3a78
        primary_llil = func.get_llil_at(addrs[-1])
        primary_hlil = primary_llil.hlil
        dest_vars = primary_hlil.ssa_form.dest.vars_read
        src_vars = primary_hlil.ssa_form.src.vars_read
        print(hex(primary_hlil.address),primary_hlil)

        if opcode == 0x008B0428:
            pass
        if len(dest_vars) == 2 and len(src_vars) == 3:
            # dest_vars [<SSAVariable: x19 version 1>, <SSAVariable: x8_3 version 2>]
            # src_vars [<SSAVariable: x19 version 1>, <SSAVariable: x9_1 version 2>, <SSAVariable: x10_32 version 2>]
            # 这种就是 reg op reg imm
            if primary_llil.operation == LowLevelILOperation.LLIL_STORE:

                # src_tree = get_llil_var_def_tree(primary_llil.ssa_form.src)
                # dest_tree = get_llil_var_def_tree(primary_llil.ssa_form.dest)
                # <LowLevelILStore: [x11 + (zx.q(w8) << 3)].q = x9>
                # <HighLevelILAssign: *(x19 - 0x130 + (zx.q(x8_3.d) << 3)) = *(x19 - 0x130 + (zx.q(x9_1.d) << 3)) + sx.q(x10_32)>
                # [vreg] = [vreg] + imm
                # generate_dot_for_llil_var(str(primary_llil.ssa_form),dest_tree)
                src_expr = []
                # dest 里面只可能是寄存器 ??
                dest_veg_var = dest_vars[1]
                dest_vreg_def = func.hlil.ssa_form.get_ssa_var_definition(dest_veg_var)
                # json.dumps(dest_tree,default=lambda o: str(o))

                # def find_callback(i):
                #
                #     return i
                # rrret = primary_llil.traverse(find_callback)
                # for i in rrret:
                #     print(i)

                """
                is_vreg = False
                for src_var in src_vars:
                    if VmContextRegister == src_var.name:
                        is_vreg = True
                        continue
                    if is_vreg:
                        # 如果是 读取 vreg
                        src_var_def = func.hlil.ssa_form.get_ssa_var_definition(src_var)
                        vreg_src_value = from_action_get_value(addr2action, src_var_def)
                        src_expr.append(vreg_src_value)
                        is_vreg =False
                    else:
                        func.llil.ssa_form.get_ssa_reg_definition(primary_llil.ssa_form.dest.operands[0].src)
                        # 不是 vreg 就是 立即数
                        # 立即数就在当前指令执行的时候去读取
                        pass
                vreg_dest = from_action_get_value(addr2action,dest_vreg_def)
                """






        # if 0x8320FACB == opcode:
        # if 0x08000A8C == opcode:
        #     for addr,actions in addr2action.items():
        #         print(f"{opcode:X}", hex(addr))
        #         print(actions)
        #     for addr, llil in addr2llil.items():
        #         print(f"{opcode:X}", hex(addr), llil)
        #
        #     json.dumps(collected_info)
        #     new_simgr = project.factory.simulation_manager(found_state)
        #     new_simgr.step()
        #     new_simgr.active[0]
        #     pass

        vm_index += 1
        vm_pc += 4
    # target_func = bin_cfg.functions.get_by_addr(start_address + 0x0009cbe0)
    # loop_state(simgr)
    # simgr.step()
    # while len(simgr.active) > 0:
    #     for active_state in simgr.active:
    #         print(hex(active_state.addr))
    #     simgr.step()



# bv = load(r"D:\TMP\libtprt.so.bndb")
# project = angr.Project('D:/TMP/libtprt.so', load_options={"auto_load_libs": False})

# Main(bv, project)
