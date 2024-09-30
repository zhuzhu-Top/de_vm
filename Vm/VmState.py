import opcode

from angr import SimStatePlugin, SimState

from Vm.VMGlobalData import VMGlobalData
import copy


#
# class VmState(SimStatePlugin):
#
#     def __init__(self, clone=None, opcodes=None, data_class=None, branch_stream=None):
#         super().__init__()
#
#         if clone is None:
#             self.opcode = opcode
#             self.dataClass = VMGlobalData() if data_class is None else data_class
#             self.branch_stream = [0] if branch_stream is None else branch_stream
#             self.opcodes = [] if opcodes is None else opcodes
#         else:
#             self.opcode = clone.opcode
#             self.dataClass = clone.dataClass
#             self.branch_stream = clone.branch_stream
#             self.opcodes = clone.opcodes
#
#     @property
#     def data(self):
#         return self.dataClass
#     def set_opcode(self, op_code):
#         self.opcode = op_code
#
#     def add_opcodes(self, _opcode):
#         self.opcodes.append(_opcode)
#
#     def add_new_branch_stream(self):
#         # copy.deepcopy(dataClass)
#         self.branch_stream.append(self.branch_stream[-1] + 1)
#
#     def set_vm_global_data(self, dataClass: VMGlobalData):
#         # copy.deepcopy(dataClass)
#         self.dataClass = VMGlobalData(dataClass.vmStates)
#
#     # copy 比 init_state 先调用
#     @SimStatePlugin.memo
#     def copy(self, memo):  # pylint: disable=unused-argument
#         return VmState(clone=self, opcodes=self.opcodes)
#
#     def init_state(self):
#         super().init_state()

# self.opcodes.append(opcode)
# 符号执行的过程会一直 创建state 然后再销毁 所以不适合放大量数据 history 会一直复制数据
# def __del__(self):
#     print(f'VmState 对象被回收--- : {self.opcodes}')


class VmState(SimStatePlugin):

        def __init__(self, clone=None):
            SimStatePlugin.__init__(self)
            if clone is None:
                self.opcodes = []
                self.current_opcode = None
                self.data = VMGlobalData()
                self.opcode_count = 0
                self.enter_exit = {}
                self.exit_opcode = None
                self.branch = []
            else:

                self.current_opcode = clone.current_opcode
                self.opcode_count = clone.opcode_count
                self.enter_exit = copy.deepcopy(clone.enter_exit)
                self.branch = copy.deepcopy(clone.branch)
                # 这里不能用浅拷贝,不然会导致state共享这个变量
                # self.opcodes = clone.opcodes
                self.opcodes = copy.deepcopy(clone.opcodes)
                # 在 angr符号执行过程会一直复制 state,这里先 浅拷贝,共享 VMGlobalData,出现分支再深拷贝
                self.data : VMGlobalData = clone.data
                self.exit_opcode = clone.exit_opcode

        def add_opcode(self, _opcode):
            self.opcode_count+=1

            self.current_opcode = _opcode

            # self.enter_exit[f"{self.opcode_count}_{self.current_opcode:X}"] =["enter"]
            # self.opcodes.append(_opcode)
            self.data.add_opcode(_opcode)
            print("add_opcode",hex(_opcode),self.opcode_count)

        def add_branch_record(self):
            self.branch.append((self.opcode_count, self.current_opcode))

        # copy 比 init_state 先调用
        @SimStatePlugin.memo
        def copy(self, memo): # pylint: disable=unused-argument
            return VmState(clone=self)

        # 为了后面写代码有提示
        @property
        def get_data(self) -> VMGlobalData:
            return self.data
# SimState.register_default('vmState', VmState)
