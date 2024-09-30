import copy
import json

import angr
import graphviz
from binaryninja import *
from pprint import pprint as pp

from utils import to_signed

VMContextReg = "x19"
VMOpcode1 = "x0"
VMOpcode2 = "x12"
StopRegisters = [
    VMContextReg,
    VMOpcode1,
    VMOpcode2
]


class BaseMatchRule:
    def __init__(self):
        pass

    def is_match(self, tree: dict) -> bool:
        pass

    def need_record(self):
        pass

    def record(self) -> dict:
        pass

    def break_after_match(self) -> bool:
        pass


class MatchOperation(BaseMatchRule):
    """
    operation      : 要匹配的 operation("any为任意的")
    left           : 左子树匹配规则
    right          : 右子树匹配规则
    record_type    : vreg 或者 const
    record_obj     : 子树的 record 返回值
    """

    def __init__(self,
                 left: BaseMatchRule,
                 right: BaseMatchRule,
                 operation: str,
                 record_type=None,
                 break_after_match=False,
                 ):
        super().__init__()
        self._break_after_match = break_after_match
        self.operation = operation
        self.left = left
        self.right = right
        self.record_type = record_type
        self.record_objs: list[BaseMatchRule] = []
        self.is_need_record = False

    def is_match(self, tree: dict) -> bool:
        # 带 operation 的应该 left right operation
        if tree.get("left") is None or tree.get("right") is None or tree.get("operation") is None:
            return False

        # if isinstance(operation,LowLevelILOperation):
        #     self.operation = operation.name
        # else:
        #     self.operation = operation
        # if tree.get("operation") == self.operation.name or self.operation == None:
        if self.operation == "any" or tree.get("operation") == self.operation:
            if self.left.is_match(tree["left"]) and self.right.is_match(tree["right"]):
                self.operation = tree.get("operation")
                return True
        return False

    def need_record(self):
        if self.left.need_record():
            self.record_objs.append(self.left)
        if self.right.need_record():
            self.record_objs.append(self.right)

        if len(self.record_objs) >= 1:
            self.is_need_record = True
            # 还需要传递
            return True
        else:
            self.is_need_record = False
            return False

    def record(self):
        if self.is_need_record:
            _ret = []
            for record_obj in self.record_objs:
                sub_ret = record_obj.record()
                if isinstance(sub_ret, list):
                    _ret.extend(sub_ret)
                else:
                    _ret.append(sub_ret)
            # 如果没设置 record_type 的话,就让 上层的来处理这个返回
            if self.record_type is None:
                return _ret
            else:
                _operation = self.operation.name if isinstance(self.operation, LowLevelILOperation) else self.operation
                return {"record_type": self.record_type,
                        "value": _ret,
                        "operation": _operation}
        return {}

    def break_after_match(self) -> bool:
        return self._break_after_match


class MatchAny(BaseMatchRule):

    def __init__(self, child: BaseMatchRule = None,record_type=None,):
        super().__init__()
        self.child = child
        self.record_type = record_type

    def is_match(self, tree: dict) -> bool:

        if self.child is not None:
            if tree.get("child") is not None:
                return self.child.is_match(tree["child"])
            else:
                # 初始化 MatchAny 的时候有值,但是便利的时候缺没有,需要返回false
                return False
        return True

    def need_record(self):
        if self.child is None:
            return super().need_record()
        return self.child.need_record()

    def record(self):
        if self.child is None:
            return super().record()

        _ret = self.child.record()
        if self.record_type is not None:
            return {"record_type": self.record_type,
                    "value": _ret}
        else:
            return _ret


class MatchExt(BaseMatchRule):

    def __init__(self):
        super().__init__()
        self.reg = None
        self.ext = None
        self.llil = None
        self.match = False

    def is_match(self, tree: dict) -> bool:
        if tree.get("ext") is None or tree.get("child") is None or tree.get("child").get("reg") is None:
            return False

        self.ext = tree.get("ext")
        self.llil = tree.get("llil")
        self.reg = tree.get("child")["reg"]
        self.match = True
        return True

    def need_record(self):
        if self.match:
            return True
        else:
            return False

    def record(self):
        if self.match:
            return {"llil": self.llil, "addr": self.llil.address, "reg": self.reg, "ext": self.ext}
        return {}


class MatchReg(BaseMatchRule):

    def __init__(self, child: BaseMatchRule=None):
        super().__init__()
        self.reg = None
        self.llil = None
        self.match = False
        self.child = child

    def is_match(self, tree: dict) -> bool:
        if tree.get("reg") is None:
            return False
        if self.child is not None and not self.child.is_match(tree["child"]):
            return False
        self.llil = tree.get("llil")
        self.reg = tree["reg"]
        self.match = True
        return True

    def need_record(self):
        if self.match:
            return True
        else:
            return False

    def record(self):
        if self.match:
            return {"llil": self.llil, "addr": self.llil.address, "reg": self.reg}
        return {}
# *(x19 - 0x130 + (zx.q(x8_3.d) << 3)) = *(x19 - 0x130 + (zx.q(x9_1.d) << 3)) | zx.q(x10_24 & 0xffff)
# 用于匹配这种 const op const 来提取某一部分
class MatchConstOpConst(BaseMatchRule):

    def __init__(self,const_value):
        super().__init__()
        self.reg = None
        self.llil = None
        self.match = False
        self.operation = False
        self.const_value = const_value

    def is_match(self, tree: dict) -> bool:
        if tree.get("right") is None or tree.get("right").get("value") is None or tree.get("left") is None or tree.get("left").get("reg") is None:
            return False
        if tree["right"]['value'] != self.const_value:
            return False

        self.llil = tree.get("llil")
        self.reg = tree.get("left")["reg"]
        self.match = True
        self.operation = tree['operation']
        return True

    def need_record(self):
        if self.match:
            return True
        else:
            return False

    def record(self):
        if self.match:
            return {"llil": self.llil,
                    "addr": self.llil.address,
                    "reg": self.reg,
                    "operation": self.operation,
                    "op_const_value": self.const_value}
        return {}

class MatchValue(BaseMatchRule):

    def __init__(self, value):
        super().__init__()
        self.value = value

    def is_match(self, tree: dict) -> bool:
        if tree.get("value") is None:
            return False
        return tree["value"] == self.value


class MatchStopReg(BaseMatchRule):

    def __init__(self):
        super().__init__()
        self.stop_reg = None
        self.record_type = "stop_reg"
    def is_match(self, tree: dict) -> bool:
        if tree.get("stop_reg") is None:
            return False
        self.stop_reg = tree.get("stop_reg")
        return True

    def need_record(self):
        if self.stop_reg is not None:
            return True
        else:
            return False

    def record(self) -> dict:
        return {
            "record_type": self.record_type,
            "stop_reg": self.stop_reg,
        }


VregRule = MatchOperation(
    operation=LowLevelILOperation.LLIL_ADD.name,
    left=MatchAny(),
    right=MatchOperation(operation=LowLevelILOperation.LLIL_LSL.name,
                         left=MatchExt(),
                         right=MatchValue(3)),
    record_type="vreg"
)
ConstRule = MatchOperation(
    operation=LowLevelILOperation.LLIL_ADD.name,
    left=MatchAny(),
    right=MatchExt(),
    record_type="const"
)

MatchVregRules = [
    MatchOperation(
        operation="any",
        left=MatchAny(
            child=MatchAny(
                child=MatchAny(
                    child=copy.deepcopy(VregRule)
                )
            )
        ),
        right=MatchAny(
            child=MatchAny(
                child=MatchAny(
                    child=copy.deepcopy(VregRule)
                )
            )
        ),
        record_type="vreg_op_vreg",
        break_after_match=True
    ),
    MatchOperation(
        operation="any",
        left=MatchAny(
            child=MatchAny(
                child=MatchAny(
                    child=copy.deepcopy(VregRule)
                )
            )
        ),
        right=MatchAny(
            child=MatchAny(
                child=MatchAny(
                    child=MatchConstOpConst(const_value=0xffff)
                )
            )
        ),
        # vreg op (vreg op const)
        record_type="vreg_op_vreg_op_value",
        break_after_match=True
    ),
    #  00002f78  *(x19 - 0x130 + (zx.q(x8_3.d) << 3)) = sx.q(*(x19 - 0x130 + (x9_1 << 3))) + sx.q(x10_32)
    MatchOperation(
        operation="any",
        left=MatchAny(
            child=MatchAny(
                child=MatchAny(
                    child=MatchAny(
                        child= MatchOperation(
                            operation="any",
                            left=MatchAny(),
                            right=MatchAny(
                                child=MatchAny(
                                    # 匹配左移三位(被左移的就是 vreg 的index)
                                    child=MatchOperation(
                                        operation=LowLevelILOperation.LLIL_LSL.name,
                                        left=MatchReg(),
                                        right=MatchValue(3),
                                        record_type="vreg"
                                    )
                                )
                            )
                        )
                    )
                )
            )
        ),
        right=MatchExt(),
        record_type="vreg_op_vreg_op_const",
        break_after_match=True
    ),
    MatchOperation(
        operation="any",
        left=MatchAny(
            child=MatchAny(
                child=MatchAny(
                    child=VregRule
                )
            )
        ),
        right=MatchExt(),
        record_type="vreg_op_const",
        break_after_match=True
    ),
    # int16_t* x9_14 = *(x19 - 0x138 + (zx.q(x9_1.d) << 3) + 8) + sx.q(x11_19 | (x14_4 u>> 0x14).w | (x13_1 u>> 0x14).w)
    # *x9_14 = *(x19 - 0x138 + (zx.q(x8_3.d) << 3) + 8)
    # 2_23BF0217
    MatchOperation(
        operation="any",
        left=MatchAny(
            child=MatchAny(
                child=MatchAny(
                    child=MatchOperation(
                        operation=LowLevelILOperation.LLIL_ADD.name,
                        left=MatchAny(
                            child=MatchAny(
                                child=VregRule
                            )
                        ),
                        right=MatchValue(8)
                    )
                )
            )
        ),
        right=MatchExt(),
        record_type="vreg_op_const",
        break_after_match=True
    ),
    MatchOperation(
        operation=LowLevelILOperation.LLIL_ADD.name,
        left=MatchAny(
            child=MatchOperation(
                operation=LowLevelILOperation.LLIL_ADD.name,
                left=MatchAny(),
                right=MatchOperation(
                    operation=LowLevelILOperation.LLIL_LSL.name,
                    left=MatchAny(
                        child=MatchAny(
                            child=MatchReg()
                        )
                    ),
                    right=MatchValue(3)
                )
            )
        ),
        right=MatchValue(8),
        record_type="vreg",
        break_after_match=True
    ),
    VregRule
]
MatchConstRules = [
    ConstRule,
    MatchAny(
        child=MatchExt(),
        record_type="const"
    ),
    MatchOperation(
        operation=LowLevelILOperation.LLIL_ADD.name,
        left=MatchStopReg(),
        right=MatchValue(-0x10),
        record_type="stop_reg"
    ),
    MatchOperation(
        operation=LowLevelILOperation.LLIL_ADD.name,
        left=MatchStopReg(),
        right=MatchValue(8),
        record_type="ip+8"
    )
]


def wrap_match(in_tree):
    index = 0
    need_break = False

    # 为了让 need_break 不上一次 匹配影响,需要再包裹一次函数
    def _match(_tree):
        _ret = []
        nonlocal index
        nonlocal need_break
        index += 1
        # 用 deepcopy 防止内部 浅拷贝 改变原始的 rule
        for rule in copy.deepcopy(MatchVregRules):
            if rule.is_match(_tree) and rule.need_record() and not need_break:
                _ret.append(rule.record())
                if rule.break_after_match():
                    need_break = True
        for rule in MatchConstRules:
            if rule.is_match(_tree) and rule.need_record() and not need_break:
                _ret.append(rule.record())
        if _tree.get("left") is not None and not need_break:
            sub_ret = _match(_tree["left"])
            _ret.extend(sub_ret)
        if _tree.get("right") is not None and not need_break:
            sub_ret = _match(_tree["right"])
            _ret.extend(sub_ret)
        if _tree.get("child") is not None and not need_break:
            sub_ret = _match(_tree["child"])
            _ret.extend(sub_ret)

        return _ret
    return _match(in_tree)
class VarAst():
    def __init__(self, func: function.Function, inst_addrs: dict[int]):
        self.right_vm_operand = None
        self.left_vm_operand = None
        # stop_reg 的情况才会设置 extra_info
        self.extra_info = None
        self.func = func
        self.llil_ssa = self.func.llil.ssa_form
        self.inst_addrs = inst_addrs
        self.primary_llil = func.get_llil_at(self.inst_addrs[0]).ssa_form
        self.create_tree_root()

    def explore_vm_object(self):
        root_left = self.tree["left"]
        root_right = self.tree["right"]
        self.left_vm_operand = wrap_match(root_left)
        self.right_vm_operand = wrap_match(root_right)

        # 左边是 stop_reg 的话 就需要全部扫描对 vreg 的操作
        # 但是当前 vm 似乎只需要找到上一体哦啊指令去构建查找 vreg 就好了
        if self.left_vm_operand[0]["record_type"] == "stop_reg":
            _llil = self.func.get_llil_at(self.inst_addrs[1]).ssa_form
            src = _llil.src
            dest = _llil.dest

            _left = self.create_llil_leaf(dest)
            _right = self.create_llil_leaf(src)
            _left_match = wrap_match(_left)
            _right_match = wrap_match(_right)

            self.extra_info = {
                "left_match": _left_match,
                "right_match": _right_match
            }
            # self.generate_dot_for_llil_var("extra_info_match",{
            #     "left": _left,
            #     "right": _right
            # })
            pass


    def create_tree_root(self):
        src = self.primary_llil.src
        dest = self.primary_llil.dest

        self.left = self.create_llil_leaf(dest)
        self.right = self.create_llil_leaf(src)
        self.tree = {
            "left": self.left,
            "right": self.right,
        }
        # self.generate_dot_for_llil_var(index_opcode,self.tree)

    def create_llil_leaf(self, llil: LowLevelILInstruction, in_addrs: dict[int] = None):

        match llil:

            case il if isinstance(il, ILRegister):
                il: ILRegister
                return {"reg": llil.name}

            case il if isinstance(il, LowLevelILRegPhi):

                phi_var_def = [self.llil_ssa.get_ssa_reg_definition(i) for i in llil.src]

                inst_addrs = self.inst_addrs if in_addrs is None else in_addrs
                for _index, addr in enumerate(inst_addrs):
                    for _var in phi_var_def:
                        if _var.address == addr:
                            if isinstance(_var, LowLevelILRegPhi):
                                # 如果还是 phi节点需要继续去查找 直接给src 就全是 变量了
                                return self.create_llil_leaf(_var, in_addrs=inst_addrs[_index + 1:])
                            else:
                                return self.create_llil_leaf(_var.src, in_addrs=inst_addrs[_index + 1:])
                raise Exception("没有匹配到")
            case il if isinstance(il, LowLevelILLowPart):
                return self.create_llil_leaf(llil.src)
            case il if isinstance(il, LowLevelILRegSsaPartial):
                llil: lowlevelil.LowLevelILRegSsaPartial
                # x9#6.w9
                # 这里拿到 要获取的部分寄存器的名字
                part_reg_name =llil.src.name
                ssa_register: lowlevelil.SSARegister = llil.full_reg
                reg = ssa_register.reg
                full_reg_name = reg.name
                if full_reg_name in StopRegisters:
                    return {"stop_reg": full_reg_name}

                def_register = self.llil_ssa.get_ssa_reg_definition(ssa_register)
                if isinstance(def_register,LowLevelILRegPhi):
                    return self.create_llil_leaf(def_register)
                return {"child": self.create_llil_leaf(def_register.src),"reg": part_reg_name,"llil": llil}

            case il if isinstance(il, LowLevelILZx) or isinstance(il, LowLevelILSx):
                _ret = self.create_llil_leaf(llil.src)

                return {"ext": llil.operation.name, "child": _ret, "llil": llil}
            case il if isinstance(il, LowLevelILConst):
                return {"value": llil.constant}

            case il if isinstance(il, LowLevelILRegSsa):
                if llil.src.reg.name in StopRegisters:
                    return {"stop_reg": llil.src.reg.name}
                def_il = self.llil_ssa.get_ssa_reg_definition(llil.src)
                _ret = self.create_llil_leaf(def_il)
                return {"child": _ret,"reg" : llil.src.reg.name, "llil": llil}

            case il if isinstance(il, LowLevelILSetReg):
                return self.create_llil_leaf(llil.src)

            case il if isinstance(il, LowLevelILSetRegSsa):
                _ret = self.create_llil_leaf(llil.src)
                return {"child": _ret, "llil": llil}
            # + - * / cmp & |
            case il if isinstance(il, LowLevelILBinaryBase):
                left = self.create_llil_leaf(llil.left)
                right = self.create_llil_leaf(llil.right)
                return {"left": left, "right": right, "operation": llil.operation.name, "llil": llil}
            case il if isinstance(il, LowLevelILLoadSsa):
                llil: LowLevelILLoadSsa
                # <LowLevelILLoadSsa: [x11#42 + (zx.q(x9#6.w9) << 3)].q @ mem#26>
                _ret = self.create_llil_leaf(llil.src)
                return {"child": _ret, "operation": llil.operation.name, "llil": llil}
            case _:
                raise Exception("未知")

    def generate_dot_for_llil_var(self, root: str, tree: dict, view=False):
        dot = graphviz.Digraph(f'{root}', comment='The Round Table')
        index = 0

        def _fill_content(parent=None, _tree=None):
            nonlocal index
            if parent is None:
                if tree.get("left") is not None:
                    left = _fill_content("root", tree["left"])
                    dot.edge(root, left)
                if tree.get("right") is not None:
                    right = _fill_content("root", tree["right"])
                    dot.edge(root, right)
                if tree.get("child"):
                    child = _fill_content("root", tree["child"])
                    dot.edge(root, child)
            else:
                current_node_text = f"{index}\n"
                has_address = False
                for key in _tree:
                    if key == "left" or key == "right" or key == "child":
                        if not has_address:
                            _address = _tree["llil"].address
                            current_node_text += f"{_address:X} \n"
                            has_address = True
                        continue
                    current_node_text += f"{key} -> {_tree[key]}\n"
                index += 1
                if _tree.get("left") is not None:
                    left = _fill_content(current_node_text, _tree["left"])
                    dot.edge(current_node_text, left)
                if _tree.get("right") is not None:
                    right = _fill_content(current_node_text, _tree["right"])
                    dot.edge(current_node_text, right)
                if _tree.get("child"):
                    child = _fill_content(current_node_text, _tree["child"])
                    dot.edge(current_node_text, child)

                return current_node_text

        _fill_content()

        dot.render(directory='doctest-output', view=view)


def from_action_get_value(addr2action,addr,reg_name):
    actions = addr2action[addr]

    for action in actions.hardcopy[::-1]:
        if isinstance(action, angr.state_plugins.SimActionData):
            if action.type == action.REG and action.WRITE and action.storage == reg_name:
                # reg/write
                bv = action.data.ast
                return bv.concrete_value,bv.length
    raise Exception("没有在action里面找到寄存器的值")

def get_full_reg(reg_name):
    return Architecture["aarch64"].regs[reg_name].full_width_reg

def from_actions_get_first_reg_value(addr2action,addr,reg_name):
    actions = addr2action[addr]
    # 这里应该先从 read 里面去找
    for action in actions:
        if isinstance(action, angr.state_plugins.SimActionData):
            if action.type == action.REG and action.READ and action.storage == reg_name:
                return action.data.ast.concrete_value

    # 不能在 addr2action[addr] 里面去找 寄存器的写入 可能存在当前指令即读取了 寄存器 又写入了这个寄存器
    while addr2action.get(addr - 4) is not None:
        actions = addr2action[addr-4]
        for action in actions[::-1]:
            if isinstance(action, angr.state_plugins.SimActionData):
                if action.type == action.REG and action.WRITE and action.storage == reg_name:
                    return action.data.ast.concrete_value
        addr = addr - 4

    raise Exception("没有在action里面找到寄存器的值")


vreg_reg = {
    0: "x0",
    1: "x1",
    3: "x3",
    4: "x4",
    29: "sp"
}
def get_reg_name(reg_index):
    if vreg_reg.get(reg_index) is not None:
        return vreg_reg.get(reg_index)
    return f"vreg_{reg_index}"

operation2sym = {
    LowLevelILOperation.LLIL_ADD.name: "+",
    LowLevelILOperation.LLIL_OR.name: "|",
    LowLevelILOperation.LLIL_AND.name: "&",
}
def get_operation(operation):
    if operation in operation2sym.keys():
        return operation2sym.get(operation)
    return operation
def decode_vm_operand(var_ast : VarAst,addr2action: dict):
    left_vm_operand = var_ast.left_vm_operand[0]
    right_vm_operand = var_ast.right_vm_operand
    right_has_record_type = False
    if len(right_vm_operand) >= 1:
        right_has_record_type = True
    if hasattr(right_vm_operand, "record_type"):
        right_has_record_type = True
    match(left_vm_operand['record_type']):
        case "vreg":
            if not right_has_record_type:
                return

            l_reg = left_vm_operand['value'][0]
            l_reg_index = from_actions_get_first_reg_value(addr2action, l_reg['addr'], get_full_reg(l_reg['reg']))

            match(right_vm_operand[0]['record_type']):
                case "vreg_op_vreg_op_const":
                    vreg1 = right_vm_operand[0]['value'][0]
                    vreg1_index = from_actions_get_first_reg_value(addr2action, vreg1['value'][0]['addr'], get_full_reg(vreg1['value'][0]['reg']))
                    const1 = right_vm_operand[0]['value'][1]
                    const1_value = from_actions_get_first_reg_value(addr2action, const1['addr'], get_full_reg(const1['reg']))
                    # print(f"vreg_{l_reg_index} = vreg_{vreg1_index} {right_vm_operand[0]['operation']} {const1_value} ")
                    print(f"{get_reg_name(l_reg_index)} = {get_reg_name(vreg1_index)} {get_operation(right_vm_operand[0]['operation'])} {const1_value} ")
                    return
                case "vreg_op_const":
                    # pass
                    r_vreg = right_vm_operand[0]['value'][0]
                    r_reg_name = get_full_reg(r_vreg['value'][0]['reg'])
                    r_const = right_vm_operand[0]['value'][1]
                    r_const_reg_name = get_full_reg(r_const['reg'])
                    r_reg_index = from_actions_get_first_reg_value(addr2action,r_vreg['value'][0]['addr'],r_reg_name)
                    r_const_value = from_actions_get_first_reg_value(addr2action,r_const['addr'],r_const_reg_name)
                    r_const_value = to_signed(r_const_value,16)


                    # print("vreg = vreg + const")
                    # print(f"vreg_{l_reg_index} = vreg_{r_reg_index} + {hex(r_const_value)}")
                    print(f"{get_reg_name(l_reg_index)} = {get_reg_name(r_reg_index)} + {hex(r_const_value)}")
                    return
                case "vreg_op_vreg":
                    vreg1 = right_vm_operand[0]['value'][0]['value'][0]
                    vreg2 = right_vm_operand[0]['value'][1]['value'][0]
                    vreg1_index = from_actions_get_first_reg_value(addr2action, vreg1['addr'],get_full_reg(vreg1['reg']))
                    vreg2_index = from_actions_get_first_reg_value(addr2action, vreg2['addr'],get_full_reg(vreg2['reg']))
                    if vreg2_index>=32:
                        # print(f"{get_reg_name(l_reg_index)} = vreg_{vreg1_index} {right_vm_operand[0]['operation']} {hex(vreg2_index)}")
                        print(f"{get_reg_name(l_reg_index)} = {get_reg_name(vreg1_index)} {get_operation(right_vm_operand[0]['operation'])} {hex(vreg2_index)}")
                    else:
                        # print(f"{get_reg_name(l_reg_index)} = {get_reg_name(vreg1_index)} {right_vm_operand[0]['operation']} {get_reg_name(vreg2_index)}")
                        print(f"{get_reg_name(l_reg_index)} = {get_reg_name(vreg1_index)} {get_operation(right_vm_operand[0]['operation'])} {get_reg_name(vreg2_index)}")
                    return
                case "const":

                    const_reg = right_vm_operand[0]['value']
                    const_value = from_actions_get_first_reg_value(addr2action, const_reg['addr'],
                                                                   get_full_reg(const_reg['reg']))
                    print(f"{get_reg_name(l_reg_index)} = {hex(const_value)}")
                    return
                case "vreg_op_vreg_op_value":
                    operation = right_vm_operand[0]['operation']
                    vreg1 = right_vm_operand[0]['value'][0]['value'][0]
                    vreg1_index = from_actions_get_first_reg_value(addr2action, vreg1['addr'],
                                                                   get_full_reg(vreg1['reg']))
                    const_op_const = right_vm_operand[0]['value'][1]
                    op2 = const_op_const['operation']
                    const_value = from_actions_get_first_reg_value(addr2action, const_op_const['addr'],
                                                                   get_full_reg(const_op_const['reg']))
                    op_const = const_op_const['op_const_value']
                    # print(f"{get_reg_name(l_reg_index)} = vreg_{vreg1_index} {operation} ({const_value}  {op2} {hex(op_const)})")
                    print(f"{get_reg_name(l_reg_index)} = {get_reg_name(vreg1_index)} {get_operation(operation)} ({hex(const_value)}  {get_operation(op2)} {hex(op_const)})")
                    return
                case _:
                    raise Exception("error")
        case "vreg_op_const":
            match (right_vm_operand[0]['record_type']):
                case "vreg":
                    r_vreg = right_vm_operand[0]
                    r_reg_index = from_actions_get_first_reg_value(addr2action,r_vreg['value'][0]['addr'],get_full_reg(r_vreg['value'][0]['reg']))

                    l_vreg = left_vm_operand['value'][0]
                    l_reg_index = from_actions_get_first_reg_value(addr2action,l_vreg['value'][0]['addr'],get_full_reg(l_vreg['value'][0]['reg']))

                    l_const = left_vm_operand['value'][1]
                    l_const_value = from_actions_get_first_reg_value(addr2action,l_const['addr'],get_full_reg(l_const['reg']))
                    # print("vreg + const = vreg")
                    # print(f"{get_reg_name(l_reg_index)} + {hex(l_const_value)} = vreg_{r_reg_index}")
                    print(f"{get_reg_name(l_reg_index)} + {hex(l_const_value)} = {get_reg_name(r_reg_index)}")
                    return
                case _:
                    raise Exception("error")
        case "stop_reg":
            vreg = var_ast.extra_info['left_match'][0]['value'][0]
            vreg_index = from_actions_get_first_reg_value(addr2action, vreg['addr'], get_full_reg(vreg['reg']))
            _right = var_ast.extra_info['right_match'][0]
            print(f"{get_reg_name(vreg_index)} = {_right['record_type']}")
        case _:
            raise Exception("error")
if __name__ == '__main__':
    bv = load(r"D:\window\AndroidRe\ttEncrypt\libEncryptor.so.bndb")
    func = bv.get_function_at(0x2c18)

    file = open("../vm_data.json", "r")
    vm_info = json.loads(file.read())
    file.close()
    for index_opcode, addrs in vm_info.items():
        addrs: list[int]
        _index_opcode = index_opcode.split("_")
        index = int(_index_opcode[0])
        opcode = int(_index_opcode[1], 16)
        llil = func.get_llil_at(addrs[0])
        print(index, _index_opcode[1], llil.operation.name, llil)
        if index_opcode == '53_8320FACB':
            var_ast = VarAst(func, addrs)
            var_ast.generate_dot_for_llil_var(index_opcode, var_ast.tree)
            var_ast.explore_vm_object()
            # decode_vm_operand(var_ast.left_vm_operand[0], var_ast.right_vm_operand,None)
            pass
        # var_ast = VarAst(func, addrs)
        # var_ast.generate_dot_for_llil_var(index_opcode, var_ast.tree)
        # var_ast.explore_vm_object()
        #
        # if len(var_ast.left_vm_operand)<1:
        #     print("未知")
        #     continue
        # if len(var_ast.right_vm_operand) < 1:
        #     print("未知")
        #     continue
        # vm_operand 转换成 binja il

        # decode_vm_operand(var_ast.left_vm_operand[0],var_ast.right_vm_operand)

        pass
        #     pp(var_ast.tree)
        # var_ast = VarAst(func,addrs)
        # pp(var_ast.tree)
