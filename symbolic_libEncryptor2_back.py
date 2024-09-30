from angr import SimulationManager
import angr
from queue import Queue
from angr.procedures.procedure_dict import SIM_PROCEDURES
from angr.sim_options import *
from pyvex.lifting.util import JumpKind
import pyvex
import json
from binaryninja import *
import logging
logging.getLogger('angr').setLevel('DEBUG')
from graphviz_tools import generate_dot_for_llil_var

project = angr.Project(r'D:\window\AndroidRe\ttEncrypt\libEncryptor.so', load_options={"auto_load_libs": False})
bv = load(r"D:\window\AndroidRe\ttEncrypt\libEncryptor.so.bndb")
func = bv.get_function_at(0x2c18)


def get_dispatcher_state(statr_addr):
    state = project.factory.blank_state(addr=statr_addr)
    state.options.add(SYMBOL_FILL_UNCONSTRAINED_MEMORY)
    state.options.add(SYMBOL_FILL_UNCONSTRAINED_REGISTERS)


    # SYMBOL_FILL_UNCONSTRAINED_
    # {MEMORY, REGISTERS}
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


def explore_vm(init_state):
    init_state.options.add(angr.options.TRACK_REGISTER_ACTIONS)

    ip_increase_addr = start_address + 0x00003a78  # ip++ 的位置
    simgr = project.factory.simulation_manager(init_state)

    def step_func(lsm: angr.SimulationManager):

        """
        if len(lsm.active) != 1:
            raise Exception("未知")
        sim_state = lsm.active[0]
        if dispatcher_addr == sim_state.addr:
            opcode = sim_state.regs.w12.v
            index2opcode[index] = opcode
            # new_simgr = project.factory.simulation_manager(new_state)
            IndexOpcode2simgr[f"{index}_{opcode:X}"] = sim_state.history.actions
            sim_state.history.trim()
            index += 1
        if start_address+0x2cd4 == sim_state.addr:
            sim_state.history.trim()
        if ip_increase_addr == sim_state.addr:
            print(f"ip increase addr : {sim_state.addr}")
        """
        return lsm

    simgr.explore(find=start_address + 0x3c18, step_func=step_func,
                  extra_stop_points=[dispatcher_addr,
                                     ip_increase_addr])

    if simgr.found:
        aaa = 0


if __name__ == '__main__':
    start_address = project.loader.min_addr

    # 负责跳转的寄存器
    state_register_name = "w12"
    # 分发器的地址(必须是第一行)
    dispatcher_addr = start_address + 0x2cd0
    # 根据函数起始地址获取分发器的初始 state
    dispatcher_state = get_dispatcher_state(start_address + 0x2ac4)

    print(f"Dispatcher state: {dispatcher_state}")
    initial_state = dispatcher_state.solver.eval_one(dispatcher_state.regs.get(state_register_name))
    print(f"Initial {state_register_name}: {hex(initial_state)}")

    collected_info = {

    }
    # explore_vm(init_state=dispatcher_state)

# bv = load(r"D:\TMP\libtprt.so.bndb")
# project = angr.Project('D:/TMP/libtprt.so', load_options={"auto_load_libs": False})

# Main(bv, project)
