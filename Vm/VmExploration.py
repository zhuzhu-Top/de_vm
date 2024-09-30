import copy
import logging

import angr
import claripy
from Vm.VmState import VmState
from .CONSTS import *
from pprint import pprint as pp

l = logging.getLogger(name=__name__)
class VmExploration(angr.ExplorationTechnique):
    def __init__(self,project_base_addr, stashes=('active', 'deferred', 'errored', 'cut')):
        super(VmExploration, self).__init__()
        self._stashes = stashes
        self.project_base_addr = project_base_addr
        self.trace_options = [
            angr.options.TRACK_OP_ACTIONS,
            angr.options.TRACK_ACTION_HISTORY,
            # 记录 寄存器 操作
            angr.options.TRACK_REGISTER_ACTIONS,
            # 记录 中间变量的操作
            angr.options.TRACK_TMP_ACTIONS
        ]

    def setup(self, simgr):
        super().setup(simgr)
        # state.register_plugin("VmState", VmState())
        simgr.stashes['active'][0].register_plugin('VmState', VmState())

    def step(self, simgr, stash="active", **kwargs):

        super_ret = super().step(simgr, stash, **kwargs)
        return super_ret

    def mem_write(self,state: angr.SimState):

        _inspect: angr.state_plugins.inspect.SimInspector = state.inspect

    # step_state 调用 successors
    def step_state(self, simgr, state, **kwargs):
        solver = state.solver
        vm_state: VmState = state.VmState
        # print(f"step_state {state.addr:X}")
        match state.addr:
            case addr if addr == self.project_base_addr + or_offset:
                print(f"{hex(state.addr)} vreg {state.regs.w10} = {state.regs.x8} | {state.regs.x9}")
            case addr if addr == self.project_base_addr + dispatcher_offset:
                self._handle_dispatcher(state)
            case addr if addr == self.project_base_addr + ip_increase_offset:
                self._handle_ip_increase(state)
            case addr if addr == self.project_base_addr + external_call_offset:
                self._handle_external_func_call(state)
            case _:
                # super_ret = super().step_state(simgr, state, **kwargs)
                pass
        return super().step_state(simgr, state, **kwargs)

    def _handle_external_func_call(self,state):
        vm_state: VmState = state.VmState
        solver = state.solver
        x0 = solver.eval_one(state.regs.x0)
        x1 = solver.eval_one(state.regs.x1)
        vm_state.data.record_ext_call(vm_state,x0)
        l.error(f"调用外部函数[{hex(vm_state.current_opcode)}] x0 = 0x{x0:X}, x1 = 0x{x1:X}", )
    def _handle_dispatcher(self,state : angr.SimState):
        solver = state.solver
        vm_state: VmState = state.VmState
        # 分发器开始
        # state.scratch.irsb.pp()
        # 读取 opcode
        x0 = state.regs.x0
        solver.eval_one(x0)
        opcode = state.memory.load(solver.eval_one(x0), 4).reversed
        opcode = solver.eval_one(opcode)

        # 调试代码
        # 如果代码没进入 ip++ 就直接重新分发了
        if vm_state.opcode_count !=0:
            # key = f"{vm_state.opcode_count}_{vm_state.current_opcode:X}"
            key = (vm_state.opcode_count,vm_state.current_opcode)
            if "exit" not in vm_state.enter_exit[key]:
                # 没进入 ip++ 就进入分发,只可能是 vm_exit 要么就应该报错
                exit_opcode = vm_state.exit_opcode
                if exit_opcode is None:
                    # 还没找到 exit_opcode 就赋值
                    # TODO 还没想好怎么处理
                    vm_state.exit_opcode = opcode
                elif exit_opcode != vm_state.current_opcode:
                    raise Exception("未知的opcode ,没有经过ip++就到了分发器")


        # 函数调用 返回无约束 防止陷入函数 (vm会调用别的vm)
        state.options.add(angr.options.CALLLESS)
        state.options.update(self.trace_options)


        vm_state.add_opcode(opcode)
        # 这里不清空的话会出现一些 上一次opcode的action 可能是angr自带的一些 option 才导致记录的action
        state.history.trim()


        # self.enter_exit[f"{self.opcode_count}_{self.current_opcode:X}"] =["enter"]
        # 必须放后面
        vm_state.enter_exit[(vm_state.opcode_count,vm_state.current_opcode)] =["enter"]

    def _handle_ip_increase(self,state):
        vm_state: VmState = state.VmState
        # ip++
        # 这里就是 当前opcode 执行结束的位置
        # 需要赋值新的 vmState 来让 一个 vmState 对应一个opcode
        # vm_state.dataClass.add_state(vm_state)
        if vm_state.current_opcode == 0x8b0428:
            pass
        x19: claripy.ast.bv.BV = state.regs.x19
        flag_value = state.mem[x19.concrete_value - 0x20].uint64_t.concrete

        if flag_value != 0:
            external_func_addr = state.mem[x19.concrete_value - 0x18].uint64_t.concrete
            l.warning(f"[{vm_state.current_opcode:X}]未知标志位 {flag_value} , {external_func_addr:X}")

        # vm_state.enter_exit[f"{vm_state.opcode_count}_{vm_state.current_opcode:X}"].append("exit")
        vm_state.enter_exit[(vm_state.opcode_count,vm_state.current_opcode)].append("exit")
        vm_state.get_data.set_history(vm_state, state.history)
        # 清空 记录的 action
        state.history.trim()

        # 从 ip++ 到重新回到分发器的过程,可能会调用 外部函数 需要特殊处理
        # 目前来看 只需要知道调用了 外部函数就可以了
        new_options = state.options.difference(self.trace_options)
        state.options = new_options
    def successors(self, simgr, state, **kwargs):
        super_ret = super().successors(simgr, state, **kwargs)

        for exit_state in list(super_ret.all_successors):
            exit_jumpkind = exit_state.history.jumpkind if exit_state.history.jumpkind else ""
            solver = exit_state.solver

            if exit_jumpkind == "Ijk_Call":
                x0 = solver.eval_one(exit_state.regs.x0)
                x1 = solver.eval_one(exit_state.regs.x1)

                l.error(f"调用外部函数[{hex(exit_state.addr)}] x0 = 0x{x0:X}, x1 = 0x{x1:X}",)

        # 当前 state 执行完之后产生了 两个分支的话 需要赋值 赋值一个全新的 VMGlobalData
        successor_len = len(super_ret.successors)
        match successor_len:
            case 2:
                for succ_state in super_ret.successors:
                    vm_state: VmState = succ_state.VmState
                    vm_state.data = copy.deepcopy(succ_state.VmState.data)
                    vm_state.add_branch_record()

            case 1:
                pass
            case _:
                raise Exception("未处理异常")
        return super_ret

