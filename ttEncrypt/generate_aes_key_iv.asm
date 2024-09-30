   pc       指令       op1       op2                 助记符
--------  --------  --------  --------  MOV     x0, #0                  ;x0始终为0，XZR寄存器?
--------  --------  --------  --------  MOV     x4, pArgs               ;pArgs={0x0: pRandNumber, 0x08:randNumberSize=0x20, 0x10:pAesKey, 0x18: aesKeyIVLen=0x10, 0x20:pAesIV, 0x28: aesKeyIVLen=0x10}
--------  --------  --------  --------  MOV     x5, #0                  
--------  --------  --------  --------  MOV     x6, pVm3_external_func_list         ;保存加密的外部函数地址列表，一共8个
--------  --------  --------  --------  MOV     x7, pCallRegisterTrampolineFunction     ;保存跳板函数地址
--------  --------  --------  --------  MOV     sp, pVirualStackBottom;                ;虚拟机堆栈栈底
--------  --------  --------  --------  MOV     lr, #0                  ;x31=0
00000000  EBBDF015  21(0x15)  --------  ADD     sp, sp, #-0x180         ;分配虚拟机堆栈
00000004  17BF0E17  23(0x17)  --------  STR     lr, [sp, #0x178]        ;保存寄存器环境
00000008  17BE0C17  23(0x17)  --------  STR     x30, [sp, #0x170]
0000000C  17B70A17  23(0x17)  --------  STR     x23, [sp, #0x168]
00000010  17B60817  23(0x17)  --------  STR     x22, [sp, #0x160]
00000014  17B50617  23(0x17)  --------  STR     x21, [sp, #0x158]
00000018  17B40417  23(0x17)  --------  STR     x20, [sp, #0x150]
0000001C  17B30217  23(0x17)  --------  STR     x19, [sp, #0x148]
00000020  17B20017  23(0x17)  --------  STR     x18, [sp, #0x140]
00000024  13B10E17  23(0x17)  --------  STR     x17, [sp, #0x138]
00000028  13B00C17  23(0x17)  --------  STR     x16, [sp, #0x130]
0000002C  00E081CB  11(0x0B)  07(0x07)  ORR     x16, x0, x7
00000030  00C10828  40(0x28)  --------  LDR     x1, [x6, #0x20]         ;<< 0xDDED44
00000034  03A10A17  23(0x17)  --------  STR     x1, [sp, #0x28]         ;>> 0xDDED44
00000038  00810A28  40(0x28)  --------  LDR     x1, [x4, #0x28]         ;<< aesIVLen=0x10
0000003C  03A10817  23(0x17)  --------  STR     x1, [sp, #0x20]         ;>> aesIVLen=0x10
00000040  00810828  40(0x28)  --------  LDR     x1, [x4, #0x20]         ;<< pAesIV
00000044  03A10617  23(0x17)  --------  STR     x1, [sp, #0x18]         ;>> pAesIV
00000048  00810628  40(0x28)  --------  LDR     x1, [x4, #0x18]         ;<< aesKeyLen=0x10
0000004C  03A10417  23(0x17)  --------  STR     x1, [sp, #0x10]         ;>> aesKeyLen=0x10
00000050  00810428  40(0x28)  --------  LDR     x1, [x4, #0x10]         ;<< pAesKey
00000054  03A10217  23(0x17)  --------  STR     x1, [sp, #0x8]          ;>> pAesKey
00000058  00D40628  40(0x28)  --------  LDR     x20, [x6, #0x18]        ;<< 0xDDEC90 
0000005C  00D20428  40(0x28)  --------  LDR     x18, [x6, #0x10]        ;<< 0xDDEC80
00000060  00950028  40(0x28)  --------  LDR     x21, [x4, #0x0]         ;<< pRandNumber
00000064  00930228  40(0x28)  --------  LDR     x19, [x4, #0x8]         ;<< randNumberSize=0x20
00000068  00D10228  40(0x28)  --------  LDR     x17, [x6, #0x8]         ;<< 0xDDEC70
0000006C  00C10028  40(0x28)  --------  LDR     x1, [x6, #0x0]          ;<< 0xDDEC54
00000070  08020015  21(0x15)  --------  ADD     x2, x0, #0x80           ;bufferSize = 0 + 0X80
00000074  13A20817  23(0x17)  --------  STR     x2, [sp, #0x120]        ;>> arg1: bufferSize = 0 + 0x80
00000078  F002F8B4  52(0x34)  --------  MOVZ    w2, #0xff22, LSL#16
                    52(0x34)  --------  SXTW    x2, w2                  ;0xFFFFFFFF:FF220000  
0000007C  84575C07  07(0x07)  --------  ORR     x23, x2, #0x5870        ;0xFFFFFFFF:FF225870 生成解密key
00000080  0037230B  11(0x0B)  12(0x0C)  ADD     x4, x23, x1             ;vm3_malloc: 0xFFFFFFFF:FF225870 + 0xDDEC54 = 0x44C4
00000084  8200C1CB  11(0x0B)  07(0x07)  ORR     x25, x0, x16            ;X25=pCallRegisterTrampolineFunction
0000008C  13A50815  21(0x15)  --------  ADD     x5, sp, #0x120          ;pArgs
00000088  8320FACB  11(0x0B)  43(0x2B)  BR      x25                     ;LR=lr,------> vm3_malloc(0x80)
00000090  13BE0A28  40(0x28)  --------  LDR     x30, [sp, #0x128]       ;<< 读取返回值 pBuffer
00000094  8237830B  11(0x0B)  12(0x0C)  ADD     x17, x23, x17           ;vm3_sha512: 0xFFFFFFFF:FF225870 + DDEC70 = 0x44E0
00000098  13A50215  21(0x15)  --------  ADD     x5, sp, #0x108          ;pArgs
0000009C  03B60C15  21(0x15)  --------  ADD     x22, sp, #0x30          ;sha512Output ,sha512长度是0x40
000000A0  13B30417  23(0x17)  --------  STR     x19, [sp, #0x110]       ;arg2: randNumberSize=0x20
000000A4  13B50217  23(0x17)  --------  STR     x21, [sp, #0x108]       ;arg1: pRandNumber,值为0x20长度的随机数
000000A8  13B60617  23(0x17)  --------  STR     x22, [sp, #0x118]       ;arg3: pSHA512Output
000000AC  8200C1CB  11(0x0B)  07(0x07)  ORR     x25, x0, x16            ;X25=pCallRegisterTrampolineFunction
000000B4  022021CB  11(0x0B)  07(0x07)  ORR     x4, x0, x17             ;跳板目标地址: 0x44E0
000000B0  8320FACB  11(0x0B)  43(0x2B)  BR      x25                     ;LR=lr,------> vm3_sha512(pRandNumber,randNumberSize,pSHA512Output)
000000B8  0257930B  11(0x0B)  12(0x0C)  ADD     x18, x23, x18           ;vm3_memcpy:  0xFFFFFFFF:FF225870 + 0xDDEC80 = 0x44F0
000000BC  0FA50C15  21(0x15)  --------  ADD     x5, sp, #0xf0           ;pArgs
000000C0  04130015  21(0x15)  --------  ADD     x19, x0, #0x40
000000C4  0FB60E17  23(0x17)  --------  STR     x22, [sp, #0xf8]        ;arg2: pSHA512Output
000000C8  0FBE0C17  23(0x17)  --------  STR     x30, [sp, #0xf0]        ;arg1: pBuffer
000000CC  13B30017  23(0x17)  --------  STR     x19, [sp, #0x100]       ;arg3: sha512Size=0x40
000000D0  8200C1CB  11(0x0B)  07(0x07)  ORR     x25, x0, x16            ;准备跳板函数
000000D8  024021CB  11(0x0B)  07(0x07)  ORR     x4, x0, x18             ;准备跳板目标
000000D4  8320FACB  11(0x0B)  43(0x2B)  BR      x25                     ;LR=lr, ------> vm3_memcpy(pBuffer, pSHA512Output, sha512Size),将sha512散列值复现到pBuffer
000000DC  0297230B  11(0x0B)  12(0x0C)  ADD     x4, x23, x20            ;vm3_decrypt: 0xFFFFFFFF:FF225870 + 0xDDEC90 = 0x4500
000000E0  0FA50615  21(0x15)  --------  ADD     x5, sp, #0xd8           ;pArgs
000000E4  0FB30817  23(0x17)  --------  STR     x19, [sp, #0xe0]        ;arg2: pos=0x40
000000E8  0FBE0617  23(0x17)  --------  STR     x30, [sp, #0xd8]        ;arg1: pBuffer
000000EC  8200C1CB  11(0x0B)  07(0x07)  ORR     x25, x0, x16            ;准备跳板函数
000000F4  0FB30A17  23(0x17)  --------  STR     x19, [sp, #0xe8]        ;arg3: size=0x40
000000F0  8320FACB  11(0x0B)  43(0x2B)  BR      x25                     ;LR=lr, ------> vm3_decrypt_seeds(pBuffer, pos, size), 复制解密的种子数据到pBuffer的pos,长度为size, pBuffer{0x0: sha512, 0x40: seedData}
000000F8  0FA50015  21(0x15)  --------  ADD     x5, sp, #0xc0           ;pArgs
000000FC  08010015  21(0x15)  --------  ADD     x1, x0, #0x80           ;BufferSize=0x80
00000100  0FA10217  23(0x17)  --------  STR     x1, [sp, #0xc8]         ;arg2: BufferSize=0x80
00000104  0FBE0017  23(0x17)  --------  STR     x30, [sp, #0xc0]        ;arg1: pBuffer
00000108  0FB60417  23(0x17)  --------  STR     x22, [sp, #0xd0]        ;arg3: pSHA512Output
0000010C  8200C1CB  11(0x0B)  07(0x07)  ORR     x25, x0, x16
00000114  022021CB  11(0x0B)  07(0x07)  ORR     x4, x0, x17             ;vm3_sha512
00000110  8320FACB  11(0x0B)  43(0x2B)  BR      x25                     ;LR=lr, ------> vm3_sha512(pBuffer,BufferSize,pSHA512Output)
00000118  0BA50A15  21(0x15)  --------  ADD     x5, sp, #0xa8           ;pArgs
0000011C  0BB60C17  23(0x17)  --------  STR     x22, [sp, #0xb0]        ;arg2: pSHA512Output
00000120  0BBE0A17  23(0x17)  --------  STR     x30, [sp, #0xa8]        ;arg1: pBuffer
00000124  0BB30E17  23(0x17)  --------  STR     x19, [sp, #0xb8]        ;arg3: sha512Size=0x40
00000128  8200C1CB  11(0x0B)  07(0x07)  ORR     x25, x0, x16
00000130  024021CB  11(0x0B)  07(0x07)  ORR     x4, x0, x18
0000012C  8320FACB  11(0x0B)  43(0x2B)  BR      x25                     ;LR=lr, ------> vm3_memcpy(pBuffer,pSHA512Output,sha512Size)
00000134  0BA50415  21(0x15)  --------  ADD     x5, sp, #0x90           ;pArgs
00000138  0BBE0617  23(0x17)  --------  STR     x30, [sp, #0x98]        ;arg2: pBuffer
0000013C  03A10228  40(0x28)  --------  LDR     x1, [sp, #0x8]          ;取出 pAesKey
00000140  0BA10417  23(0x17)  --------  STR     x1, [sp, #0x90]         ;arg1: pAesKey
00000144  03B10428  40(0x28)  --------  LDR     x17, [sp, #0x10]        ;取出 aesKeyLen
00000148  0BB10817  23(0x17)  --------  STR     x17, [sp, #0xa0]        ;arg3: aesKeyLen
0000014C  8200C1CB  11(0x0B)  07(0x07)  ORR     x25, x0, x16
00000154  024021CB  11(0x0B)  07(0x07)  ORR     x4, x0, x18
00000150  8320FACB  11(0x0B)  43(0x2B)  BR      x25                     ;LR=lr, ------> vm3_memcpy(pAesKey, pBuffer, aesKeyLen)
00000158  83D1030B  11(0x0B)  12(0x0C)  ADD     x1, x17, x30            ;pDst = pBuffer + aesKeyLen
0000015C  07A50E15  21(0x15)  --------  ADD     x5, sp, #0x78           ;pArgs: 准备参数指针
00000160  0BA10017  23(0x17)  --------  STR     x1, [sp, #0x80]         ;arg2: pDst
00000164  03A10628  40(0x28)  --------  LDR     x1, [sp, #0x18]
00000168  07A10E17  23(0x17)  --------  STR     x1, [sp, #0x78]         ;arg1: pAesIV
0000016C  03A10828  40(0x28)  --------  LDR     x1, [sp, #0x20]
00000170  0BA10217  23(0x17)  --------  STR     x1, [sp, #0x88]         ;arg3: aesIVLen
00000174  8200C1CB  11(0x0B)  07(0x07)  ORR     x25, x0, x16
0000017C  024021CB  11(0x0B)  07(0x07)  ORR     x4, x0, x18
00000178  8320FACB  11(0x0B)  43(0x2B)  BR      x25                     ;LR=lr, ------> vm3_memcpy(pAesIV, pDst, aesIVLen)
00000180  03A10A28  40(0x28)  --------  LDR     x1, [sp, #0x28]         
00000184  0037230B  11(0x0B)  12(0x0C)  ADD     x4, x23, x1             ;vm3_free: 0xFFFFFFFF:FF225870 + 0xDDED44 = 0x45B4
00000188  07A50C15  21(0x15)  --------  ADD     x5, sp, #0x70           ;pArgs
0000018C  8200C1CB  11(0x0B)  07(0x07)  ORR     x25, x0, x16
00000194  07BE0C17  23(0x17)  --------  STR     x30, [sp, #0x70]        ;arg1: pBuffer
00000190  8320FACB  11(0x0B)  43(0x2B)  BR      x25                     ;LR=lr, ------> vm3_free(pBuffer)
00000198  13B00C28  40(0x28)  --------  LDR     x16, [sp, #0x130]       ;恢复寄存器环境
0000019C  13B10E28  40(0x28)  --------  LDR     x17, [sp, #0x138]
000001A0  17B20028  40(0x28)  --------  LDR     x18, [sp, #0x140]
000001A4  17B30228  40(0x28)  --------  LDR     x19, [sp, #0x148]
000001A8  17B40428  40(0x28)  --------  LDR     x20, [sp, #0x150]
000001AC  17B50628  40(0x28)  --------  LDR     x21, [sp, #0x158]
000001B0  17B60828  40(0x28)  --------  LDR     x22, [sp, #0x160]
000001B4  17B70A28  40(0x28)  --------  LDR     x23, [sp, #0x168]
000001B8  17BE0C28  40(0x28)  --------  LDR     x30, [sp, #0x170]
000001BC  17BF0E28  40(0x28)  --------  LDR     lr, [sp, #0x178]
000001C4  1BBD0015  21(0x15)  --------  ADD     sp, sp, #0x180
000001C0  03E00F8B  11(0x0B)  62(0x3E)  ExitVm       0                  ;lr

已知指令统计:
op1: 21                 使用次数: 15
op1: 23                 使用次数: 38
op1: 40                 使用次数: 27
op1: 52                 使用次数: 1
op1: 7                  使用次数: 1
op1: 11 op2: 7          使用次数: 16
op1: 11 op2: 12         使用次数: 6
op1: 11 op2: 43         使用次数: 9
op1: 11 op2: 62         使用次数: 1