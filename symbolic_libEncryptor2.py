import itertools
import json
from array import array
from typing import Dict, List

import angr
import faulthandler
import logging
import copy
import pyvex
from angr.state_plugins import SimStateHistory

from Vm import *
from Vm.BinjaAst import VarAst, decode_vm_operand
from Vm.CONSTS import *
import binaryninja as binja
from itertools import groupby

from graphviz_tools import generate_dot_for_llil_var
from utils import get_llil_var_def_tree
from vm_tools import VmIL, VmConst

# import colorlog
# logging.getLogger('angr').setLevel('DEBUG')

logger = logging.getLogger('angr')
# logger.setLevel(logging.INFO)
logger.setLevel(logging.ERROR)

bv = binja.load(r"D:\window\AndroidRe\ttEncrypt\libEncryptor.so.bndb")
func = bv.get_function_at(0x2c18)
project = angr.Project(r'D:\window\AndroidRe\ttEncrypt\libEncryptor.so', load_options={"auto_load_libs": False})

start_address = project.loader.min_addr


def collect_llil_action(_history: SimStateHistory):
    addr2llil = {}
    addr2action = {}
    # actions_len = len(_history.actions)
    last_ins_addr = 0
    last_llil = 0
    addrs = []
    for index,action in enumerate(history.actions):
        ins_addr = action.ins_addr-start_address
        # 跟上一个action的地址不一样才收集
        if ins_addr != last_ins_addr:
            current_llil = func.get_llil_at(ins_addr)
            if current_llil == last_llil:
                # 上一个跟 现在的 llil是一样的话,就把上一个删掉
                del addr2llil[last_ins_addr]
            addr2llil[ins_addr] = current_llil
            addrs.append(ins_addr)
        if addr2action.get(ins_addr) is None:
            addr2action[ins_addr] = [action]
        else:
            addr2action[ins_addr].append(action)

        last_ins_addr = ins_addr

    addrs.reverse()

    # 这种写法会遇到写奇怪的东西
    # for index,action in enumerate(history.actions):
    #     ins_addr = action.ins_addr - start_address
    #     current_llil = func.get_llil_at(ins_addr)
    #     if ins_addr != last_action_addr:
    #         addr2action[current_llil.address] = [action]
    #         last_action_addr = current_llil.address
    #
    #
    #         addr2llil[current_llil.address] = current_llil
    #     else:
    #         addr2action[current_llil.address].append(action)

    # for addr,llil in addr2llil.items():
    #     print(hex(addr),llil)
    #     for action in addr2action[addr]:
    #         print("\t",action)
    return addrs,addr2llil,addr2action


def from_action_get_value(addr2action,hlil : binja.HighLevelILInstruction):
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
if __name__ == '__main__':
    faulthandler.enable()  # start @ the beginning
    state = project.factory.blank_state(addr=start_address+0x2AC4)
    project.factory.block(0x402394).vex

    simgr = project.factory.simgr(state)
    simgr.use_technique(VmExploration(start_address))
    # simgr.explore(find=start_address+0x3c18, extra_stop_points=[or_addr])

    simgr.explore(find=start_address+0x4440,
                  extra_stop_points=
                        [start_address+i for i in
                                    [
                                    or_offset,
                                    dispatcher_offset,
                                    external_call_offset,
                                    ip_increase_offset
                                    ]
                         ],
                        # [start_address+or_offset,
                        #  start_address+dispatcher_offset,
                        #  start_address+external_call_offset],
                  # num_find=1,
                  num_find=100,
                  fail_fast=True
                  )
    # simgr.explore(find=start_address+0x2c20,num_find=1)
    if simgr.found:
        # for found_state in simgr.found[2]:
        found_state = simgr.found[2]
        # found_state = simgr.found[0]
        data: VMGlobalData = found_state.VmState.data

        vm_info = {}
        for index_opcode,history in data.history:
            history: SimStateHistory
            # 最后一个 指令来
            last_ins_addr = history.actions[-1].ins_addr - start_address
            primary_llil = func.get_llil_at(last_ins_addr)

            if primary_llil.operation == binja.LowLevelILOperation.LLIL_STORE:

                primary_hlil_ssa = primary_llil.hlil.ssa_form

                addrs,addr2llil,addr2action = collect_llil_action(history)
                str_index_opcode = f"{index_opcode[0]}_{index_opcode[1]:X}"
                vm_info[f"{str_index_opcode}"] = list(addrs)
                if index_opcode[0] == 28:
                    print("branch0(先不处理)")
                    continue
                var_ast = VarAst(func, addrs)
                var_ast.generate_dot_for_llil_var(str_index_opcode, var_ast.tree)
                var_ast.explore_vm_object()

                if len(var_ast.left_vm_operand) < 1:
                    print("未知")
                    continue
                if len(var_ast.right_vm_operand) < 1:
                    print("未知")
                    continue
                # print(f"{index_opcode[0]}_{index_opcode[1]:X}")
                if index_opcode[0] == 40:
                    pass

                decode_vm_operand(var_ast,addr2action)
            else:
                # 不是store就是 if ==> 跳转指令
                addrs = []
                for i in history.actions:
                    addrs.append(i.ins_addr-start_address)
                for k,g in groupby(addrs):
                    _llil = func.get_llil_at(k)
                    # print(hex(_llil.address),_llil)
                # print(f"{primary_llil.operation} {primary_llil.address:X}: {primary_llil}")
            # print(history)

            if data.opcode_index2_ext_call.get(index_opcode) is not None:
                ext_call_addr = data.opcode_index2_ext_call.get(index_opcode)
                ext_call_addr -= start_address
                print(f"call {hex(ext_call_addr)}")
                pass
        with open("./vm_data.json","w") as f:
            f.write(json.dumps(vm_info))


