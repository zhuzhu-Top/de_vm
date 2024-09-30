
import angr
import faulthandler
import logging
import copy
import pyvex
from Vm import *

# import colorlog
# logging.getLogger('angr').setLevel('DEBUG')

# logger = logging.getLogger('angr')
# logger.setLevel(logging.INFO)

project = angr.Project(r'D:\window\AndroidRe\ttEncrypt\libEncryptor.so', load_options={"auto_load_libs": False})

start_address = project.loader.min_addr

dispatcher_addr = start_address + 0x2cc8
or_addr = start_address + 0x3920


if __name__ == '__main__':
    faulthandler.enable()  # start @ the beginning

    state = project.factory.blank_state(addr=start_address+0x2AC4)

    state.register_plugin("VmState",VmState())


    simgr = project.factory.simgr(state)
    # simgr.use_technique(VmExploration(start_address))
    # simgr.explore(find=start_address+0x3c18, extra_stop_points=[or_addr])
    # simgr.explore(find=start_address+0x4440,
    #               extra_stop_points=[or_addr,dispatcher_addr],num_find=1)
    simgr.explore(find=start_address+0x2c20,num_find=1)
    if simgr.found:

        found_state = simgr.found[0]
        found_state.options.add(angr.options.CALLLESS)

        def my_engine_process(state):
            if state.addr == dispatcher_addr:
                solver =state.solver
                x0 = state.regs.x0
                solver.eval_one(x0)
                opcode = state.memory.load(solver.eval_one(x0), 4).reversed
                opcode = solver.eval_one(opcode)
                state.VmState.add_opcode(opcode)


        found_state.inspect.make_breakpoint("engine_process",when=angr.BP_BEFORE,action=my_engine_process)
        new_simgr = project.factory.simgr(found_state)
        new_simgr.explore(find=start_address+0x4440,
                          extra_stop_points=[or_addr,dispatcher_addr],num_find=100)
        if new_simgr.found:

        # for found in simgr.found:
        # for t_state in simgr.found[0].VmState.dataClass.vmStates:
        #     t_state : VmState
        #     print(hex(t_state.opcode))
            print(new_simgr.found)

