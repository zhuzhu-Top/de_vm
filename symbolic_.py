from angr import SimulationManager
import angr
from queue import Queue
from angr.procedures.procedure_dict import SIM_PROCEDURES
from pyvex.lifting.util import JumpKind


def loop_state(simgr : SimulationManager):

    # if simgr.successors(state).is_empty:
    #     return
    new_state = simgr.step()
    while len(simgr.active) > 0:
        for active_index,active in enumerate(simgr.active):
            for index,suc in enumerate(new_state.successors(active)):
                print(hex(active.addr),f" - [{active_index}][{index}]->  " ,hex(suc.addr))
        print("*"*10)
        new_state = simgr.step()
    # for index,active_state in enumerate(simgr.active):
    #     print(hex(state.addr) ,f" - [{index}]->  " , hex(active_state.addr))
    #     loop_state(simgr,active_state)

project = angr.Project('D:/TMP/libtprt.so', load_options={"auto_load_libs": False})

def get_dispatcher_state(function):
    state = project.factory.call_state(addr=function)
    # Ignore function calls
    # https://github.com/angr/angr/issues/723
    state.options.add(angr.options.CALLLESS)
    simgr = project.factory.simulation_manager(state)
    # Find the dispatcher
    # while True:
    #     simgr.step()
    #     assert len(simgr.active) == 1
    #     state = simgr.active[0]
        # if state.addr == dispatcher:
        # return state.copy()
    # 直接使用上面的 strp无法停在分发器的开始位置,所以不能按照文章上的写
    simgr.explore(find=dispatcher_addr)
    if simgr.found:
        _init = simgr.found[0]
        return _init.copy()
    else:
        raise Exception("未找到分发器")

def find_successors(state_value, dispatcher,debug = False):
    state = dispatcher_state.copy()
    setattr(state.regs,state_register_name,state.solver.BVV(state_value, 64))
    simgr = project.factory.simulation_manager(state)
    # 必须先step一下 不然就直接结束了
    new_sm = simgr.step()
    back_state = new_sm.active[0]

    if debug and state_value == 0xf3498be1:
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
        solutions = found_state.solver.eval_upto(getattr(found_state.regs,state_register_name), 2)
        return found_state, solutions
    else:
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


# state_value => real basic block state
states = {}

if __name__ == '__main__':

    start_address = project.loader.min_addr
    # state = project.factory.blank_state(addr=start_address + 0x0009cbe0, remove_options={angr.sim_options.LAZY_SOLVES})
    # simgr = project.factory.simulation_manager(state)
    # simgr = project.factory.successors(state)
    # project.hook(start_address+0x9ccdc, angr.SIM_PROCEDURES["stubs"]["ReturnUnconstrained"](), replace=True)
    # simgr.explore(find=start_address+0x9cd14)
    # bin_cfg = project.analyses.CFGFast(
    #     regions=[(start_address+0x9ccdc,start_address+0x9cd14)],
    #     normalize=True,
    #     resolve_indirect_jumps=True,
    #     data_references=True,
    #     )
    # dispatcher_addr = start_address+0x9cc54
    # dispatcher_state = get_dispatcher_state(start_address + 0x0009cbe0)
    # 负责跳转的寄存器
    state_register_name = "x22"
    # 分发器的地址(必须是第一行)
    dispatcher_addr = start_address+0x9cf7c
    # 根据函数起始地址获取分发器的初始 state
    dispatcher_state = get_dispatcher_state(start_address + 0x9ceb8)

    print(f"Dispatcher state: {dispatcher_state}")
    initial_state = dispatcher_state.solver.eval_one(dispatcher_state.regs.get(state_register_name))
    print(f"Initial {state_register_name}: {hex(initial_state)}")

    q = Queue()
    q.put(initial_state)
    while not q.empty():
        state_value = q.get()
        # Skip visited states
        if state_value in states:
            continue

        bb_state, successors = find_successors(state_value,dispatcher_addr,False)

        states[state_value] = bb_state, successors
        for state_value in successors:
            q.put(state_value)

    for state_value,values in states.items():
        _state: angr.SimState = values[0]
        successors = values[1]
        if len(successors) >0 :
            #条件跳转
            print(f"{hex(state_value)}  ==>",hex(_state.history.addr -start_address),[hex(i) for i in successors])
        else:
            print(f"{hex(state_value)}  ==>",hex(_state.history.addr), " [ret] ")

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
