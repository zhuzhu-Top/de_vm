import struct

registers_name_64 = [
    "x0",
    "x1",
    "x2",
    "x3",
    "x4",
    "x5",
    "x6",
    "x7",
    "x8",
    "x9",
    "x10",
    "x11",
    "x12",
    "x13",
    "x14",
    "x15",
    "x16",
    "x17",
    "x18",
    "x19",
    "x20",
    "x21",
    "x22",
    "x23",
    "x24",
    "x25",
    "x26",
    "x27",
    "x28",
    "sp",
    "x30",
    "lr"
]
registers_name_32 = [
    "w0",
    "w1",
    "w2",
    "w3",
    "w4",
    "w5",
    "w6",
    "w7",
    "w8",
    "w9",
    "w10",
    "w11",
    "w12",
    "w13",
    "w14",
    "w15",
    "w16",
    "w17",
    "w18",
    "w19",
    "w20",
    "w21",
    "w22",
    "w23",
    "w24",
    "w25",
    "w26",
    "w27",
    "w28",
    "wsp",
    "w30",
    "w31"
]

branch_control_flow = False
asm_code = ""
pipeline = 0


def get_regsiter_name(reg, bit=64):
    if bit == 64:
        return registers_name_64[reg]
    else:
        return registers_name_32[reg]

def get_op1(opcode):
    return opcode & 0x3F

def get_op2(opcode):
    return (opcode >> 6) & 0x3F

def get_imm16(opcode, sign=True):
    # opcode[15-12] | opcode[31->11] | opcode[30->10] | opcode[29->9] | opcode[28->8] | opcode[27->7] | opcode[26->6] | opcode[11-6->5-0]   
    result = (opcode & 0xF000) |  (opcode >> 20 & 0xFC0) | (opcode >> 6 & 0x3F)
    if result & 0x8000 and sign:
        return result | ~0xFFFF
    else:
        return result
    
def get_imm26(opcode, sign=True):
    # opcode[25-12] | opcode[31->11] | opcode[30->10] | opcode[29->9] | opcode[28->8] | opcode[27->7] | opcode[26->6] | opcode[11-6->5-0]
    result = get_imm16(opcode, False)
    return result | (opcode & 0x3FFF000)

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

def set_branch_control(asm):
    global branch_control_flow, asm_code
    branch_control_flow = True
    asm_code = asm

def branch_pipeline_process():
    global pipeline
    global branch_control_flow, asm_code
    if branch_control_flow:
        pipeline += 4
        if pipeline == 8:
            print(asm_code)
            branch_control_flow = False
            asm_code = ""
            pipeline = 0

def record_insns(status, known_insns_op1, known_insns_op2, unknown_insts_op1, unknown_insts_op2, opcode):
    op1 = get_op1(opcode)
    op2 = get_op2(opcode)
    match status:
        case 1:
            c = known_insns_op1.get(op1, None) 
            if c == None:
                known_insns_op1[op1] = 1
            else:
                known_insns_op1[op1] += 1
        case 2:
            c = known_insns_op2.get(op2, None)
            if c == None:
                known_insns_op2[op2] = 1
            else:
                known_insns_op2[op2] += 1
        case 3:           
            unknown_insts_op1.add(op1)
        case 4:
            unknown_insts_op2.add(op2)

def decode_statistics(known_insns_op1, known_insns_op2, unknown_insts_op1, unknown_insts_op2):
    print("\n已知指令统计:")
    for k, v in known_insns_op1.items():
        print(f"op1: {k}\t\t\t使用次数: {v}")
    for k, v in known_insns_op2.items():
        print(f"op1: {11}\top2: {k}\t\t使用次数: {v}")
    if len(unknown_insts_op1) > 0 or len(unknown_insts_op2) > 0:
        print("\n未解码指令统计:")
        for v in unknown_insts_op1:
            print(f"op1: {v}")
        for v in unknown_insts_op2:
            print(f"op2: {11}  op2: {v}")
    print("\n")

def decode(pcode_start, pcode_size, liner_disasm = False):
    with open("libEncryptor.so", "rb") as f:
        content = f.read()

    print(f"{'pc':^8} {'指令':^8}  {'op1':^8}  {'op2':^8}\t{'助记符':^30}")
    print(f"{'-'*8}  {'-'*8}  {'-'*8}  {'-'*8}  MOV\tx0, #0\t\t\t;x0始终为0，XZR寄存器?")
    print(f"{'-'*8}  {'-'*8}  {'-'*8}  {'-'*8}  MOV\tx4, pArgs\t\t;参数列表指针")
    print(f"{'-'*8}  {'-'*8}  {'-'*8}  {'-'*8}  MOV\tx5, #0")
    print(f"{'-'*8}  {'-'*8}  {'-'*8}  {'-'*8}  MOV\tx6, pfn_external_func_list\t\t;外部函数列表指针")
    print(f"{'-'*8}  {'-'*8}  {'-'*8}  {'-'*8}  MOV\tx7, pCallRegisterTrampolineFunction\t;保存跳转函数地址")
    print(f"{'-'*8}  {'-'*8}  {'-'*8}  {'-'*8}  MOV\tx29, pVirualStackBottom;\t\t;虚拟机堆栈栈底")
    print(f"{'-'*8}  {'-'*8}  {'-'*8}  {'-'*8}  MOV\tlr, #0\t\t\t;x31=0")
        
    # 已解析的指令
    known_insns_op1 = {}        # dcode_insns_status=1
    known_insns_op2 = {}        # dcode_insns_status=2
    # 未解析的指令
    unknown_insts_op1 = set()   # dcode_insns_status=3
    unknown_insts_op2 = set()   # dcode_insns_status=4
    bytes_code = content[pcode_start : pcode_start + pcode_size]
    
    for pc in range(0, pcode_size, 4):
        word = struct.unpack("<I", bytes_code[pc : pc + 4])  
        asm = ""         
        dcode_insns_status = 0
        if len(word) > 0:
            opcode = word[0]            
            op1 = get_op1(opcode)
            Xt = get_openand1(opcode)   # x8/w8
            Xn = get_operand2(opcode)   # x9/w9    
            Xm = get_operand3(opcode)   # x10/w10
            X4 = get_operand4(opcode)   # x11/w11
            match op1:
                case 11:
                    Xt = get_operand3(opcode)   # x10/w10
                    Xn = get_openand1(opcode)   # x8/w8
                    Xm = get_operand2(opcode)   # x9/w9                 
                    op2 = get_op2(opcode)                    
                    match op2:
                        case 7:
                            dcode_insns_status=2
                            print(f"{pc:08X}  {opcode:08X}  {opcode & 0x3F:02d}(0x{opcode & 0x3F:02X})  {op2:02d}(0x{op2:02X})\tORR\t{get_regsiter_name(Xt)}, {get_regsiter_name(Xn)}, {get_regsiter_name(Xm)}")
                        case 12:
                            dcode_insns_status=2
                            print(f"{pc:08X}  {opcode:08X}  {opcode & 0x3F:02d}(0x{opcode & 0x3F:02X})  {op2:02d}(0x{op2:02X})\tADD\t{get_regsiter_name(Xt)}, {get_regsiter_name(Xn)}, {get_regsiter_name(Xm)}")
                        case 25:
                            dcode_insns_status=2
                            if X4 == 0:
                                print(f"{pc:08X}  {opcode:08X}  {opcode & 0x3F:02d}(0x{opcode & 0x3F:02X})  {op2:02d}(0x{op2:02X})\tNOP\t\t\t\t;LSL\t{get_regsiter_name(Xt)}, {get_regsiter_name(Xn)}, #{X4}")
                            else:
                                print(f"{pc:08X}  {opcode:08X}  {opcode & 0x3F:02d}(0x{opcode & 0x3F:02X})  {op2:02d}(0x{op2:02X})\tLSL)\t{get_regsiter_name(Xt)}, {get_regsiter_name(Xn)}, #{X4}")
                        case 39:
                            dcode_insns_status=2
                            print(f"{pc:08X}  {opcode:08X}  {opcode & 0x3F:02d}(0x{opcode & 0x3F:02X})  {op2:02d}(0x{op2:02X})\tCMP\t{get_regsiter_name(Xm)}, {get_regsiter_name(Xn)}")
                            print(f"{' '*8}  {' '*8}  {opcode & 0x3F:02d}(0x{opcode & 0x3F:02X})  {op2:02d}(0x{op2:02X})\tCSET\t{get_regsiter_name(Xt)}, CC")
                        case 43:
                            dcode_insns_status=2
                            if liner_disasm:
                                print(f"{pc:08X}  {opcode:08X}  {opcode & 0x3F:02d}(0x{opcode & 0x3F:02X})  {op2:02d}(0x{op2:02X})\tBR\t{get_regsiter_name(Xm)}\t\t\t;LR={get_regsiter_name(Xt)}")
                            else:
                                asm = f"{pc:08X}  {opcode:08X}  {opcode & 0x3F:02d}(0x{opcode & 0x3F:02X})  {op2:02d}(0x{op2:02X})\tBR\t{get_regsiter_name(Xm)}\t\t\t;LR={get_regsiter_name(Xt)}"
                                set_branch_control(asm)
                        case 62:
                            dcode_insns_status=2
                            if liner_disasm:
                                print(f"{pc:08X}  {opcode:08X}  {opcode & 0x3F:02d}(0x{opcode & 0x3F:02X})  {op2:02d}(0x{op2:02X})\tExitVm\t0\t\t\t;{get_regsiter_name(Xm)}")
                            else:
                                asm = f"{pc:08X}  {opcode:08X}  {opcode & 0x3F:02d}(0x{opcode & 0x3F:02X})  {op2:02d}(0x{op2:02X})\tExitVm\t0\t\t\t;{get_regsiter_name(Xm)}"
                                set_branch_control(asm)
                        case _:
                            dcode_insns_status=4
                            print(f"{pc:08X}  {opcode:08X}  {opcode & 0x3F:02d}(0x{opcode & 0x3F:02X})  {op2:02d}(0x{op2:02X})\t>> op2_xxx\t{get_regsiter_name(Xt)}, {get_regsiter_name(Xn)}, {get_regsiter_name(Xm)}")
                case 7:
                    dcode_insns_status = 1
                    imm16 = get_imm16(opcode)
                    print(f"{pc:08X}  {opcode:08X}  {opcode & 0x3F:02d}(0x{opcode & 0x3F:02X})  {'-'*8}\tORR\t{get_regsiter_name(Xt)}, {get_regsiter_name(Xn)}, #{hex(imm16)}")
                case 12:
                    dcode_insns_status = 1
                    imm26 = get_imm26(opcode)
                    offset = imm26 * 4
                    if liner_disasm:
                        print(f"{pc:08X}  {opcode:08X}  {opcode & 0x3F:02d}(0x{opcode & 0x3F:02X})  {'-'*8}\tB\t{hex(offset)}")
                    else:
                        asm = f"{pc:08X}  {opcode:08X}  {opcode & 0x3F:02d}(0x{opcode & 0x3F:02X})  {'-'*8}\tB\t{hex(offset)}"
                        set_branch_control(asm)
                case 17:
                    dcode_insns_status = 1
                    imm16 = get_imm16(opcode)
                    print(f"{pc:08X}  {opcode:08X}  {opcode & 0x3F:02d}(0x{opcode & 0x3F:02X})  {'-'*8}\tADD\t{get_regsiter_name(Xt)}, {get_regsiter_name(Xn)}, #{hex(imm16)}")
                case 21:
                    dcode_insns_status = 1
                    imm16 = get_imm16(opcode)
                    print(f"{pc:08X}  {opcode:08X}  {opcode & 0x3F:02d}(0x{opcode & 0x3F:02X})  {'-'*8}\tADD\t{get_regsiter_name(Xt)}, {get_regsiter_name(Xn)}, #{hex(imm16)}")
                case 23:
                    dcode_insns_status = 1
                    imm16 = get_imm16(opcode)
                    print(f"{pc:08X}  {opcode:08X}  {opcode & 0x3F:02d}(0x{opcode & 0x3F:02X})  {'-'*8}\tSTR\t{get_regsiter_name(Xt)}, [{get_regsiter_name(Xn)}, #{hex(imm16)}]")
                case 24:
                    dcode_insns_status = 1
                    imm16 = get_imm16(opcode)
                    offset = pc + imm16 * 4 + 4
                    if liner_disasm:
                        print(f"{pc:08X}  {opcode:08X}  {opcode & 0x3F:02d}(0x{opcode & 0x3F:02X})  {'-'*8}\tB.HS\t#{hex(offset)}\t\t\t;{get_regsiter_name(Xt)}, {get_regsiter_name(Xn)}, ${hex(imm16 * 4)}")
                    else:
                        asm = f"{pc:08X}  {opcode:08X}  {opcode & 0x3F:02d}(0x{opcode & 0x3F:02X})  {'-'*8}\tB.HS\t#{hex(offset)}\t\t\t;{get_regsiter_name(Xt)}, {get_regsiter_name(Xn)}, ${hex(imm16 * 4)}"
                        set_branch_control(asm)
                case 40:
                    dcode_insns_status = 1
                    imm16 = get_imm16(opcode)
                    print(f"{pc:08X}  {opcode:08X}  {opcode & 0x3F:02d}(0x{opcode & 0x3F:02X})  {'-'*8}\tLDR\t{get_regsiter_name(Xt)}, [{get_regsiter_name(Xn)}, #{hex(imm16)}]")
                case 48:
                    dcode_insns_status = 1
                    imm16 = get_imm16(opcode)
                    print(f"{pc:08X}  {opcode:08X}  {opcode & 0x3F:02d}(0x{opcode & 0x3F:02X})  {'-'*8}\tSTR\t{get_regsiter_name(Xt, 32)}, [{get_regsiter_name(Xn)}, #{hex(imm16)}]")
                case 52:
                    dcode_insns_status = 1
                    imm16 = get_imm16(opcode, False)
                    print(f"{pc:08X}  {opcode:08X}  {opcode & 0x3F:02d}(0x{opcode & 0x3F:02X})  {'-'*8}\tMOVZ\t{get_regsiter_name(Xt, 32)}, #{hex(imm16)}, LSL#16")
                    print(f"{' '*8}  {' '*8}  {opcode & 0x3F:02d}(0x{opcode & 0x3F:02X})  {'-'*8}\tSXTW\t{get_regsiter_name(Xt)}, {get_regsiter_name(Xt, 32)}")
                case _:
                    dcode_insns_status=3                   
                    print(f"{pc:08X}  {opcode:08X}  {opcode & 0x3F:02d}(0x{opcode & 0x3F:02X})  {'-'*8}\t>> op1_xxx\t{get_regsiter_name(Xt)}, {get_regsiter_name(Xn)}, {get_regsiter_name(Xm)}")
            if not liner_disasm:
                branch_pipeline_process()
            record_insns(dcode_insns_status, known_insns_op1, known_insns_op2, unknown_insts_op1, unknown_insts_op2, opcode)
        else:
            print("error")    
    decode_statistics(known_insns_op1, known_insns_op2, unknown_insts_op1, unknown_insts_op2)

def main():
    # 解码vm2
    pcode_start = 0xB090
    pcode_size = 0x2D8
    decode(pcode_start, pcode_size)

    # # 解码vm3,获取aes的key和iv
    pcode_start = 0xBDE0
    pcode_size = 0x1C8
    # decode(pcode_start, pcode_size)
    
    # 解码vm1,JNI_OnLoad
    pcode_start = 0x85C0
    pcode_size = 0xCC
    # decode(pcode_start, pcode_size)

if __name__ == "__main__":
    main()
