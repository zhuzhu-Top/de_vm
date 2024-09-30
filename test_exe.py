from itertools import groupby

import angr
from VMEngine import VmEngine


project = angr.Project(r'D:\window\code\c++\MesonX\buildDir\main.exe',
                       engine=VmEngine,
                       load_options={"auto_load_libs": False})


def get_dispatcher_state():
    state = project.factory.blank_state(addr=start_addr + 0x1000)
    blokc_vex = project.factory.block(addr=start_addr + 0x1000).vex

    state.options.add(angr.options.TRACK_OP_ACTIONS)
    state.options.add(angr.options.TRACK_ACTION_HISTORY)
    state.options.add(angr.options.TRACK_REGISTER_ACTIONS)

    state.regs.rcx = state.solver.BVS("rcx", 64, uninitialized=True)
    state.regs.rdx = state.solver.BVS("rdx", 64, uninitialized=True)
    simgr = project.factory.simulation_manager(state)

    # bin_cfg = project.analyses.CFGFast(
    #     regions=[(start_addr+0x1000,start_addr+0x103C)],
    #     normalize=True,
    #     resolve_indirect_jumps=True,
    #     data_references=True,
    #     )

    # 这个函数是step成功之后调用的
    def step_func(lsm: angr.SimulationManager):

        return lsm

    # simgr.explore(find=start_addr + 0x3c18, step_func=step_func, num_find=10,
    #               extra_stop_points=[start_addr + 0x100E, start_addr + 0x1038])
    simgr.explore(find=start_addr+0x103C,step_func=step_func,num_find=10)

    if simgr.found:
        _init = simgr.found[0]
        return _init.copy()
    else:
        raise Exception("未找到分发器")


if __name__ == '__main__':

    for k, g in groupby('AAAABBBCCDAABBB'):
        pass


    start_addr = project.loader.min_addr

    get_dispatcher_state()
