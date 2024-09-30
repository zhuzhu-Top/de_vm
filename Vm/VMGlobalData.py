# 全局唯一的
import copy

from angr.state_plugins import SimStateHistory

from Vm import VmState


class VMGlobalData():
    def __init__(self,
                 opcode2history=None,
                 opcode_index2_ext_call=None,
                 opcode_count=0,
                 parent=None):

        self.opcode2history = {} if opcode2history is None else opcode2history
        self.opcode_index2_ext_call = {} if opcode_index2_ext_call is None else opcode_index2_ext_call
        self.opcode_count = opcode_count
        self.parent: VMGlobalData = None if parent is None else parent

        # self.history: "SimStateHistory"
        # print("VMGlobalData 初始化")

    @property
    def get_history(self):
        return self.opcode2history

    @property
    def history(self):
        # 如果有父类，优先获取父类的历史记录
        if self.parent:
            yield from self.parent.history  # 递归获取父类的历史记录
        # 返回当前对象的历史记录
        yield from self.opcode2history.items()
    def set_history(self, vm_state: VmState, history: SimStateHistory):
        # self.opcode2history[f"{vm_state.opcode_count}_{vm_state.current_opcode:X}"] = history
        self.opcode2history[(vm_state.opcode_count,vm_state.current_opcode)] = history

    def add_opcode(self, opcode):
        self.opcode_count += 1

    # 记录外部调用的函数
    def record_ext_call(self,vm_state,ext_func_addr):
        self.opcode_index2_ext_call[(self.opcode_count, vm_state.current_opcode)] = ext_func_addr

    def add_branch(self, vm_state):
        self.branch.append((vm_state.opcode_count,vm_state.current_opcode))
    # def __del__(self):
    #     print(f'TestClas 对象被回收--- : {self.opcodes}')
    def __deepcopy__(self, memodict={}):
        # 检查对象是否已经在 memodict 中
        if id(self) in memodict:
            return memodict[id(self)]
        return VMGlobalData(
            opcode_count=self.opcode_count,
            parent=self,
            opcode_index2_ext_call=copy.deepcopy(self.opcode_index2_ext_call),
        )
