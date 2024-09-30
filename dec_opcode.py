import os

#
# for i in range(int(0x538/8)):
#     print(hex(int(i*8)))
import struct

pcode_start = 0xB090
pcode_size = 0x2D8
with open(r"D:\window\AndroidRe\ttEncrypt\libEncryptor.so", "rb") as f:
    content = f.read()
bytes_code = content[pcode_start: pcode_start + pcode_size]
def un():

    insts_sets = {}
    for pc in range(0, pcode_size, 4):
        word = struct.unpack("<I", bytes_code[pc: pc + 4])
        if len(word) > 0:
            opcode = word[0]
            op1 = opcode & 0x3F
            if insts_sets.get(op1, None) == None:
                insts_sets[op1] = 1
            else:
                insts_sets[op1] += 1
    sorted_dict = dict(sorted(insts_sets.items(), key=lambda item: item[1], reverse=True))
    for inst, count in sorted_dict.items():
        print(f'op1: {inst} [{hex(inst)}], count: {count}', hex(0xab24 + (inst << 2)))


def pb(value):
    binary_representation = f"{value:032b}"
    header = ""
    for i in range(32):
        _str = f"{i:<3d}"
        header = f"{_str}{header}"
    header+="\r\n"
    for i in range(32):
        _str = f"{binary_representation[i]:<3s}"
        header+=_str
    print(header)
# Rotate left: 0b1001 --> 0b0011
rol = lambda val, r_bits, max_bits: \
    (val << r_bits%max_bits) & (2**max_bits-1) | \
    ((val & (2**max_bits-1)) >> (max_bits-(r_bits%max_bits)))
# Rotate right: 0b1001 --> 0b1100
ror = lambda val, r_bits, max_bits: \
    ((val & (2**max_bits-1)) >> r_bits%max_bits) | \
    (val << (max_bits-(r_bits%max_bits)) & (2**max_bits-1))
def get_imm16(opcode, sign=True):
    # opcode[15-12] | opcode[31->11] | opcode[30->10] | opcode[29->9] | opcode[28->8] | opcode[27->7] | opcode[26->6] | opcode[11-6->5-0]
    result = (opcode & 0xF000) |  (opcode >> 20 & 0xFC0) | (opcode >> 6 & 0x3F)
    if result & 0x8000 and sign:
        return result | ~0xFFFF
    else:
        return result


def get_openand1(opcode):
    # w8
    return opcode >> 16 & 0x1F


def get_operand2(opcode):
    #    w9
    return opcode >> 21 & 0x1F


def get_operand3(opcode):
    # w10
    return ((opcode & 0xF000) >> 11) | \
        opcode >> 31


def get_operand4(opcode):
    #  w11
    return opcode >> 26 & 0x1F

def get_op1(opcode):
    return opcode & 0x3F
def outer_decode():
    for pc in range(0, pcode_size, 4):
        word = struct.unpack("<I", bytes_code[pc: pc + 4])
        if len(word) > 0:

            opcode = word[0]
            print(hex(opcode),",")
            op1 = get_op1(opcode)
            Xt = get_openand1(opcode)   # x8/w8
            Xn = get_operand2(opcode)   # x9/w9
            Xm = get_operand3(opcode)   # x10/w10
            X4 = get_operand4(opcode)   # x11/w11

            # if opcode ==
            match op1:
                case 11:
                    jump_key = ror(((opcode & 0xfff) - 0xb),6,32)
                    print(f'opcode[1]:{opcode & 0x3f} hex(bv.parse_expression("(([0xa6a0 + {hex((opcode & 0x3f) << 2)}].d)+0xa6a0) & 0xffffffff"))  ')
                    print(f'opcode[2]:{opcode & 0x3f} hex(bv.parse_expression("(([0xadb0 + {hex(jump_key << 2)}].d)+0xadb0) & 0xffffffff"))  ')

                case 23:


                    print(f'opcode[1]:{opcode & 0x3f} hex(bv.parse_expression("(([0xa6a0 + {hex((opcode & 0x3f) << 2)}].d)+0xa6a0) & 0xffffffff"))  ')
                    print(f'opcode[2]:{opcode & 0x3f} hex(bv.parse_expression("(([0xab24 + {hex(((opcode & 0x3f) - 0x14) << 2)}].d)+0xab24) & 0xffffffff"))  ')
                    print(f"opcode: str {op1}[{hex(op1)}] Xt:{Xt:>2d} Xn:{Xn:>2d} imm:{hex(get_imm16(opcode))} ")
                    pass
                case 21:
                    print(f'opcode[1]:{opcode & 0x3f} hex(bv.parse_expression("(([0xa6a0 + {hex((opcode & 0x3f) << 2)}].d)+0xa6a0) & 0xffffffff"))  ')
                    print(f"opcode: add {op1}[{hex(op1)}] Xt:{Xt:>2d} Xn:{Xn:>2d} imm:{hex(get_imm16(opcode))} ")
                    pass
                    aaa=0
                # 0x2e50 0x3380

                # print(f'opcode[2]:{w12 & 0x3f} hex(bv.parse_expression("(([0xab24 + {hex(((w12 & 0x3f)-0x14)<<2)}].d)+0xab24) & 0xffffffff"))  ')



outer_decode()
        # hex(0xffffffff & bv.parse_expression("[0xa6fc].d")+0xa6a0)
 # hex(0xffffffff & bv.parse_expression("[0xa6fc].d")+0xab24)