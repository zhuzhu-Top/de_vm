import copy
from typing import Type, Optional, Tuple, TypeVar

T = TypeVar('T')

from binaryninja import *
from pprint import pprint as pp
import unittest

"""
最终放弃这种方式 ,不太聪明的样子,也不直观,很难继续(放弃屎山)

这个文件是特别为当前 vm 写的, 用于提取出 虚拟寄存器 和 真实寄存器的对应关系
然后才可以去 actions中提取相应的寄存器的写入 就可以拿到 到底是哪个 vreg 了 

本来是用的 python 字典直接传的 但是没有代码提示,但是写完发现这样也没有代码提示

这里面的代码只适用于当前分析的vm,并不通用
"""


@dataclass(frozen=False, repr=True, eq=True)
class VmIL(object):
    def __init__(self, binja_il :HighLevelILInstruction, addr=None,
                 parse_il = False,
                 ext_type=None,
                 operation = None,
                 addrs = None):
        super().__init__()
        self.ext_type = ext_type
        self.binja_il = binja_il
        if addrs is not None:
            self.addrs = copy.deepcopy(list(addrs))
            self.addrs.reverse()
            # 用的时候要先使用后面的地址
        # 两边操作数 vreg 的 个数
        self.reg_count = {
            "left": 0,
            "right": 0,

        }
        # 两边操作数 const 的 个数
        self.const_count ={
            "left": 0,
            "right": 0,
        }

        # 提前声明left和right，使用Optional类型以便获得代码提示
        self.left: Optional[Union['VmVreg', 'VmConst']] = None
        self.right: Optional[Union['VmVreg', 'VmConst']] = None
        # 是二元操作的 话 这里就有 operation
        self.operation = operation

        self.addr = addr

        if parse_il:
            self.parse_il()
            self.count_reg_const()

    def get_of_type(self, attr: str, type_: T) -> Optional[T]:
        """
        通用函数来获取left或right中的某个类型值
        :param attr: 'left' 或 'right'
        :param type_: 要检查的类型实例，例如 VmVreg, VmConst
        :return: 返回匹配的类型值，或者 None 如果没有找到
        """
        value = getattr(self, attr, None)
        if type(value) == type_:
            return value
        return None
    @staticmethod
    def extract_ext_type(il):
        if isinstance(il, HighLevelILZx):
            return HighLevelILOperation.HLIL_ZX
        elif isinstance(il, HighLevelILSx):
            return HighLevelILOperation.HLIL_SX
        raise Exception("参数错误")


    @staticmethod
    def extract_vreg_info_from_hlil_defer(hlil, deref=False):
        if deref is False and not isinstance(hlil, HighLevelILDerefSsa):
            raise Exception("不是 解引用 可能不是 vreg")

        def find_extension(inst: HighLevelILInstruction) -> int:
            if isinstance(inst, HighLevelILZx) or isinstance(inst, HighLevelILSx):
                return inst

        find_ils = [i for i in hlil.traverse(find_extension, shallow=True)]
        if len(find_ils) == 0:
            return None,None,None
        il =find_ils[0]
        # <HighLevelILDerefSsa: *(x19#1 - 0x138 + (zx.q(x9_1#2.d) << 3) + 8) @ mem#13>

        # 返回物理寄存的名字 用于 去 action 中读取 这个虚拟寄存器的偏移
        real_reg_name = il.llil.src.src.name
        ext_type = VmIL.extract_ext_type(il)
        return real_reg_name, il.address, ext_type

    @staticmethod
    def extract_src_dest(il):
        src = il.src
        dest = il.dest
        return src, dest

    def count_reg_const(self):
        # 两边操作数 vreg 的 个数
        # self.reg_count = (0, 0)
        # 两边操作数 const 的 个数
        # self.const_count = (0, 0)

        self._inner_count_reg(self.left,"left")
        self._inner_count_reg(self.right,"right")
    def _inner_count_reg(self,vm_il,postion):
        if vm_il.operation == None:
            # 不是二元操作 那就只有一个操作数
            if isinstance(vm_il,VmVreg):
                self.reg_count[postion] += 1
            if isinstance(vm_il,VmConst):
                self.const_count[postion] += 1
        else:
            vm_left = vm_il.left
            vm_right = vm_il.right
            if isinstance(vm_left,VmVreg):
                self.reg_count[postion] += 1
            if isinstance(vm_left,VmConst):
                self.const_count[postion] += 1
            if isinstance(vm_right,VmVreg):
                self.reg_count[postion] += 1
            if isinstance(vm_right,VmConst):
                self.const_count[postion] += 1

    def parse_il(self):
        src, dest = self.extract_src_dest(self.binja_il)
        src_vm_il = self.parse_il_operands(src)
        dest_vm_il = self.parse_il_operands(dest)

        self.left = dest_vm_il
        self.right = src_vm_il
        self.operation = "="

    def parse_il_operands(self, hlil_ssa: HighLevelILInstruction,deref = False,plus_eight= False):
        """
        解析传入的 il，返回 VmVreg 或 VmConst 或者两者的组合。
        """

        match hlil_ssa:
            case il if isinstance(il, BinaryOperation):
                # 假设两个操作数都是 vreg
                op0 = hlil_ssa.operands[0]
                op1 = hlil_ssa.operands[1]
                #
                if isinstance(op0,HighLevelILSx) and isinstance(op0.src,HighLevelILDerefSsa):
                    op0 = op0.src
                if (isinstance(op0,HighLevelILDerefSsa)
                        and (isinstance(op1,HighLevelILSx)
                             or isinstance(op1,HighLevelILZx)
                             or isinstance(op1,HighLevelILDerefSsa))):
                    ret_il = VmIL(hlil_ssa)
                    ret_il.left = self.parse_il_operands(op0,deref = deref,plus_eight=True)
                    ret_il.operation = hlil_ssa.operation
                    ret_il.right = self.parse_il_operands(op1,deref = deref,plus_eight=True)
                    return ret_il
                elif isinstance(op0,HighLevelILVarSsa) and isinstance(op1,HighLevelILConst):
                    # var + const(8)
                    # 上面有解引用 加上 这里 +8 这种是 vreg计算的过程被分开了
                    if deref and op1.value.value != 8:
                        raise Exception("未知表达式")

                    return self.parse_il_operands(op0,deref = deref,plus_eight=True)
                elif isinstance(op0,HighLevelILSub) and isinstance(op1,HighLevelILLsl):
                    # 这种 没 +8 的 就需要 减 0x130
                    is_ok = False
                    # if plus_eight is False and op0.right.constant == 0x130:
                    if op0.right.constant == 0x130 or op0.right.constant == 0x138:
                        is_ok = True
                    if op1.right.constant != 3 and not deref :
                        is_ok = False
                    # 减的右边应该是 0x138
                    # op0 : <HighLevelILSub: x19#1 - 0x138>
                    # op1 : <HighLevelILLsl: zx.q(x8_3#2.d) << 3>
                    if not is_ok:
                        raise Exception("未知表达式")
                    reg2vreg, vreg_addr, ext_type = self.extract_vreg_info_from_hlil_defer(hlil_ssa,deref =deref)
                    if ext_type is None:
                        raise Exception("未知表达式")
                    return VmVreg(il, reg2vreg, vreg_addr, ext_type)
                else:
                    raise Exception("未知表达式")
            case il if isinstance(il, HighLevelILSx) or isinstance(il, HighLevelILZx):
                #    <HighLevelILSx: sx.q(x10_32#2)>
                # reg_name = hlil_ssa.src.llil.src.src.name
                if isinstance(hlil_ssa.llil.src,LowLevelILAnd) and isinstance(hlil_ssa.llil.src.right,LowLevelILConst) and 0xffff == hlil_ssa.llil.src.right.constant:
                    reg_name = hlil_ssa.llil.src.left.src.name
                elif isinstance(hlil_ssa.llil.src.src,ILRegister):
                    reg_name = hlil_ssa.llil.src.src.name
                else:
                    reg_name = hlil_ssa.llil.src.src.src.name
                const_ext_type = extract_ext_type(hlil_ssa)
                return VmConst(hlil_ssa,reg_name,hlil_ssa.address,const_ext_type)

            case il if isinstance(il, HighLevelILDerefSsa):
                # 处理 vreg 解引用的情况
                reg2vreg, vreg_addr, ext_type = self.extract_vreg_info_from_hlil_defer(hlil_ssa,deref =deref)
                if ext_type is None:
                    return self.parse_il_operands(hlil_ssa.operands[0],deref = True,plus_eight=plus_eight)
                    # def_hlil_ssa = hlil_ssa.function.get_ssa_var_definition(hlil_ssa.operands[0])
                    # return self.parse_il_operands(def_hlil_ssa.src)
                return VmVreg(il,reg2vreg,vreg_addr,ext_type)
            case il if isinstance(il, HighLevelILVarPhi):

                start_flag = False
                var_name = hlil_ssa.src[0].name
                # [<SSAVariable: x9_8 version 2>, <SSAVariable: x9_8 version 3>, <SSAVariable: x9_8 version 4>, <SSAVariable: x9_8 version 5>, <SSAVariable: x9_8 version 6>, <SSAVariable: x9_8 version 7>, <SSAVariable: x9_8 version 8>, <SSAVariable: x9_8 version 9>, <SSAVariable: x9_8 version 10>, <SSAVariable: x9_8 version 11>, <SSAVariable: x9_8 version 12>, <SSAVariable: x9_8 version 13>, <SSAVariable: x9_8 version 15>, <SSAVariable: x9_8 version 18>]
                for index, addr in enumerate(self.addrs):
                    if addr == hlil_ssa.address:
                        start_flag = True
                    if start_flag:
                        _llil = hlil_ssa.function._source_function.get_llil_at(addr)
                        if _llil.hlil is None:
                            # jump 这种指令就没有 hlil 直接跳过
                            continue
                        _jlil_ssa = _llil.hlil.ssa_form
                        _vars_written = _jlil_ssa.vars_written

                        _find_flags = [True if i.name == var_name else False for i in _vars_written]
                        if True in _find_flags:
                            return self.parse_il_operands(_jlil_ssa.src,deref = deref,plus_eight=True)
                raise Exception("未知表达式")
            case il if isinstance(il, HighLevelILVarInitSsa):
                # 暂借直接解析 src 交给下面继续处理
                return self.parse_il_operands(hlil_ssa.src,deref = deref,plus_eight=True)
            case il if isinstance(il, HighLevelILVarSsa):

                # 这段代码狗都不看(完全是为了代码能跑完,已经不择手段了)
                def_hlil_ssa = hlil_ssa.function.get_ssa_var_definition(hlil_ssa.operands[0])
                if def_hlil_ssa.address == hlil_ssa.address and isinstance(def_hlil_ssa,HighLevelILVarPhi):
                    # 就在这里处理了,不然下面的  phi节点的处理就太复杂了
                    phi_var_def = [hlil_ssa.function.get_ssa_var_definition(i) for i in def_hlil_ssa.src]
                    _addrs = [i.address for i in phi_var_def]
                    for addr in self.addrs:
                        if addr in _addrs:
                            index = _addrs.index(addr)
                            def_var = phi_var_def[index]
                            if isinstance(def_var,HighLevelILVarPhi):
                                # 继续交给下面处理
                                break
                            return self.parse_il_operands(def_var.src, deref=deref, plus_eight=plus_eight)
                return self.parse_il_operands(def_hlil_ssa,deref = deref,plus_eight=True)
            case il if isinstance(il, HighLevelILConst):

                return VmConst(il,None,il.constant,None)

            case _:
                raise Exception("未知的 IL 类型")

    def __str__(self):
        return f"VmIL(left={self.left}, right={self.right},operation= {self.operation.name})"

    def __repr__(self):
        return self.__str__()
@dataclass(frozen=False, repr=True, eq=True)
class VmVreg(VmIL):

    def __init__(self, binja_il, reg, addr,ext_type):
        super().__init__(binja_il=binja_il, addr=addr, ext_type=ext_type)
        # 对应的真实寄存器的名字
        self.reg = reg

    def __str__(self):
        return f"VmVreg(reg={self.reg})"

@dataclass(frozen=False, repr=True, eq=True)
class VmConst(VmIL):

    def __init__(self, binja_il, const_reg, addr,ext_type):
        super().__init__(binja_il=binja_il, addr=addr, ext_type=ext_type)
        self.const_reg = const_reg
    def __str__(self):
        return f"VmConst(const_reg={self.const_reg})"


def extract_ext_type(il):
    if isinstance(il, HighLevelILZx):
        return HighLevelILOperation.HLIL_ZX
    elif isinstance(il, HighLevelILSx):
        return HighLevelILOperation.HLIL_SX
    raise Exception("参数错误")


class TestMethods(unittest.TestCase):

    def setUp(self):
        super().setUp()

        bv = load(r"D:\window\AndroidRe\ttEncrypt\libEncryptor.so.bndb")
        self.func = bv.get_function_at(0x2c18)

    def test_store(self):
        # vreg + const = vreg
        primary_llil = self.func.get_llil_at(0x3388)

        primary_hlil_ssa = primary_llil.hlil.ssa_form

        vm_il = VmIL(primary_hlil_ssa,parse_il=True)

        vm_right = vm_il.right
        vm_left = vm_il.left


        self.assertEqual(vm_left.left.reg, 'w9')
        self.assertEqual(vm_left.left.addr, 0x2e70)
        self.assertEqual(vm_left.operation,HighLevelILOperation.HLIL_ADD)
        self.assertEqual(vm_left.right.const_reg, "w11")
        self.assertEqual(vm_left.right.addr, 11924)


        self.assertEqual(vm_right.reg, 'w8')
        self.assertEqual(vm_right.addr, 0x3380)




    def test_add(self):
        # 0x3054
        # vreg + const = vreg
        primary_llil = self.func.get_llil_at(0x3388)

        primary_hlil_ssa = primary_llil.hlil.ssa_form

        vm_il = VmIL(primary_hlil_ssa, parse_il=True)

        vm_right = vm_il.right
        vm_left = vm_il.left

        self.assertEqual(vm_left.left.reg, 'w9')
        self.assertEqual(vm_left.left.addr, 0x2e70)

        self.assertEqual(vm_left.operation,HighLevelILOperation.HLIL_ADD)

        self.assertEqual(vm_left.right.const_reg, "w11")
        self.assertEqual(vm_left.right.addr, 0x2e94)

        self.assertEqual(vm_right.reg, 'w8')
        self.assertEqual(vm_right.addr, 0x3380)

    def test_or(self):
        primary_llil = self.func.get_llil_at(0x3924)

        primary_hlil_ssa = primary_llil.hlil.ssa_form

        vm_il = VmIL(primary_hlil_ssa, parse_il=True)



        vm_right = vm_il.right
        self.assertEqual(vm_right.left.reg, 'w8')
        self.assertEqual(vm_right.left.addr, 0x391c)

        self.assertEqual(vm_right.right.reg,    'w9')
        self.assertEqual(vm_right.right.addr, 0x3918)

        self.assertEqual(vm_right.operation,HighLevelILOperation.HLIL_OR)

        vm_left = vm_il.left

        self.assertEqual(vm_left.reg, 'w10')
        self.assertEqual(vm_left.addr, 0x3924)

    def test_vreg_plus_const_eq_vreg(self):
        # vreg + const = vreg
        primary_llil = self.func.get_llil_at(0x3054)

        primary_hlil_ssa = primary_llil.hlil.ssa_form

        vm_il = VmIL(primary_hlil_ssa, parse_il=True)


        # 左边

        vm_right = vm_il.right
        self.assertEqual(vm_right.operation,HighLevelILOperation.HLIL_ADD)
        self.assertEqual(vm_right.left.reg, 'w9')
        self.assertEqual(vm_right.left.addr, 0x304c)
        self.assertEqual(vm_right.right.const_reg, 'w10')
        self.assertEqual(vm_right.right.addr, 0x3050)

        vm_left = vm_il.left

        self.assertEqual(vm_left.reg, 'w8')
        self.assertEqual(vm_left.addr, 0x3054)

#
    def test_ldr(self):
        primary_llil = self.func.get_llil_at(0x3a74)

        primary_hlil_ssa = primary_llil.hlil.ssa_form

        addrs = [0x3920,0x3924,0x2cc8,0x2cd0,0x2cd4,0x2cdc,0x2ce0,0x2ce4,0x2ce8,0x2cec,0x2cf0,0x2cf4,0x2cf8,0x2cfc,0x2d00,0x2d04,0x2d08,0x2d0c,0x2d10,0x2d14,0x2d18,0x2d1c,0x2d20,0x2d24,0x2d28,0x2d2c,0x2d30,0x2d34,0x2d38,0x2d3c,0x2d40,0x2d44,0x2d4c,0x2d50,0x2d54,0x2d58,0x2d5c,0x2d60,0x2d64,0x2d68,0x2d6c,0x2d70,0x2d74,0x2d78,0x2d7c,0x2d80,0x2d84,0x2d88,0x3318,0x3a70,0x3a74]
        vm_il = VmIL(primary_hlil_ssa, parse_il=True,addrs=addrs)

        vm_right = vm_il.right
        vm_left = vm_il.left

        self.assertEqual(vm_right.operation,HighLevelILOperation.HLIL_ADD)
        self.assertEqual(vm_right.left.reg, 'w9')
        self.assertEqual(vm_right.left.addr, 0x2d60)
        self.assertEqual(vm_right.right.const_reg, 'w11')
        self.assertEqual(vm_right.right.addr, 0x2d84)

        self.assertEqual(vm_left.reg, 'w8')
        self.assertEqual(vm_left.addr, 0x3a70)

    def test_set_vreg_flag(self):
        # 0x3f08 [x8].q = x24
        primary_llil = self.func.get_llil_at(0x3f08)

        primary_hlil_ssa = primary_llil.hlil.ssa_form

        addrs = [0x3a70,0x3a74,0x2cc8,0x2cd0,0x2cd4,0x2cdc,0x2ce0,0x2ce4,0x2ce8,0x2cec,0x2cf0,0x2cf4,0x2cf8,0x2cfc,0x2d00,0x2d04,0x2d08,0x2d0c,0x2d10,0x2d14,0x2d18,0x2d1c,0x2d20,0x2d24,0x2d28,0x2d2c,0x2d30,0x2d34,0x2d38,0x2d3c,0x3098,0x309c,0x30a0,0x30a8,0x30ac,0x30b0,0x30b4,0x3f18,0x3f1c,0x3f20,0x3f24,0x3f28,0x3f2c,0x3f08]
        vm_il = VmIL(primary_hlil_ssa, parse_il=True,addrs=addrs)

        vm_right = vm_il.right
        vm_left = vm_il.left

        self.assertEqual(vm_right.addr,1)


        self.assertEqual(vm_left.reg, 'w10')
        self.assertEqual(vm_left.addr, 0x3f28)

if __name__ == '__main__':
    unittest.main()
