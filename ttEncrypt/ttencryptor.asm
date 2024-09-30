   pc       指令       op1       op2                 助记符
--------  --------  --------  --------  MOV     x0, #0                  ;x0始终为0，XZR寄存器?
--------  --------  --------  --------  MOV     x4, pArgs               ;pArgs={0x0:pScrBuffer, 0x8:srcSize, 0x10:pDstBuffer, 0x18:pDestBuffSize}
--------  --------  --------  --------  MOV     x5, #0                  
--------  --------  --------  --------  MOV     x6, pVm2_external_func_list               ;保存加密的外部函数地址列表，一共8个
--------  --------  --------  --------  MOV     x7, pCallRegisterTrampolineFunction       ;保存跳板函数地址
--------  --------  --------  --------  MOV     sp, pVirualStackBottom;				         ;虚拟机堆栈栈底
--------  --------  --------  --------  MOV     lr, #0					   ;x31=0
00000000  DFBDFC15  21(0x15)  --------  ADD     sp, sp, #-0x210         ;分配堆栈
00000004  23BF0217  23(0x17)  --------  STR     lr, [sp, #0x208]        ;保存寄存器环境
00000008  23BE0017  23(0x17)  --------  STR     x30, [sp, #0x200]
0000000C  1FB70E17  23(0x17)  --------  STR     x23, [sp, #0x1f8]
00000010  1FB60C17  23(0x17)  --------  STR     x22, [sp, #0x1f0]
00000014  1FB50A17  23(0x17)  --------  STR     x21, [sp, #0x1e8]
00000018  1FB40817  23(0x17)  --------  STR     x20, [sp, #0x1e0]
0000001C  1FB30617  23(0x17)  --------  STR     x19, [sp, #0x1d8]
00000020  1FB20417  23(0x17)  --------  STR     x18, [sp, #0x1d0]
00000024  1FB10217  23(0x17)  --------  STR     x17, [sp, #0x1c8]
00000028  1FB00017  23(0x17)  --------  STR     x16, [sp, #0x1c0]
0000002C  00E081CB  11(0x0B)  07(0x07)  ORR     x16, x0, x7             ;mov x16, pCallRegisterTrampolineFunction
00000030  008B0428  40(0x28)  --------  LDR     x11, [x4, #0x10]        ;pDstBuffer
00000034  008C0028  40(0x28)  --------  LDR     x12, [x4, #0x0]         ;pScrBuffer
00000038  00C20028  40(0x28)  --------  LDR     x2, [x6, #0x0]          ;base + 0xDDD2D0 = 0x2B40
0000003C  00C30228  40(0x28)  --------  LDR     x3, [x6, #0x8]          ;base + 0xDDD2EC = 0x2B5C
00000040  00C50428  40(0x28)  --------  LDR     x5, [x6, #0x10]         ;base + 0xDDD324 = 0x2B94
00000044  00C70628  40(0x28)  --------  LDR     x7, [x6, #0x18]         ;base + 0xDDD338 = 0x2BA8
00000048  00C80828  40(0x28)  --------  LDR     x8, [x6, #0x20]         ;base + 0xDDD348 = 0x2BB8
0000004C  00C90A28  40(0x28)  --------  LDR     x9, [x6, #0x28]         ;base + 0xDDD358 = 0x2BC8
00000050  00920628  40(0x28)  --------  LDR     x18, [x4, #0x18]        ;pDestBuffSize
00000054  00CA0C28  40(0x28)  --------  LDR     x10, [x6, #0x30]        ;base + 0xDDD378 = 0x2BE8
00000058  00C60E28  40(0x28)  --------  LDR     x6, [x6, #0x38]         ;base + 0xDDD394 = 0x2C04
0000005C  00930228  40(0x28)  --------  LDR     x19, [x4, #0x8]         ;srcSize
00000060  06610D95  21(0x15)  --------  ADD     x1, x19, #0x76          ;addSrcSize = srcSize + 0x76
00000064  0BA10217  23(0x17)  --------  STR     x1, [sp, #0x88]         ;保存 addSrcSize
00000068  02440028  40(0x28)  --------  LDR     x4, [x18, #0x0]         ;dstBuffSize，从指针从取出目标缓冲区大小
0000006C  808109CB  11(0x0B)  39(0x27)  CMP     x4, x1
                    11(0x0B)  39(0x27)  CSET    x1, CC
00000074  0000064B  11(0x0B)  25(0x19)  NOP                             ;LSL    x0, x0, #0
00000070  002000D8  24(0x18)  --------  B.HS    #0x80                   ;x0, x1, $0xc，如果dstBuffSize > addSrcSize并跳转到pc偏移0x80
0000007C  02400017  23(0x17)  --------  STR     x0, [x18, #0x0]
00000078  08000A8C  12(0x0C)  --------  B       0x2a8                   ;dstBuffSize < addSrcSize跳转到pc偏移0x2a8,并准备返回子程序
00000080  F001F8B4  52(0x34)  --------  MOVZ    w1, #0xff22, LSL#16     
                    52(0x34)  --------  SXTW    x1, w1                  ;0xFFFFFFFF:FF220000      
00000084  84215C07  07(0x07)  --------  ORR     x1, x1, #0x5870         ;0xFFFFFFFF:FF225870 生成解密key
00000088  00C1230B  11(0x0B)  12(0x0C)  ADD     x4, x1, x6              ;base + 0x2C04 = base + 0xDDD394 + 0xFFFFFFFFFF225870 
0000008C  07A40017  23(0x17)  --------  STR     x4, [sp, #0x40]         ;vm2_free: base + 0x2C04
00000090  0141230B  11(0x0B)  12(0x0C)  ADD     x4, x1, x10             ;base + 0x2BE8 = base + 0xDDD378 + 0xFFFFFFFFFF225870 
00000094  03A40E17  23(0x17)  --------  STR     x4, [sp, #0x38]         ;vm2_aes: base + 0x2BE8
00000098  0121230B  11(0x0B)  12(0x0C)  ADD     x4, x1, x9              ;base + 0x2BC8 = base + 0xDDD358 + 0xFFFFFFFFFF225870 
0000009C  03A40C17  23(0x17)  --------  STR     x4, [sp, #0x30]         ;vm2_memcpy_with_flags: base + 0x2BC8
000000A0  0101230B  11(0x0B)  12(0x0C)  ADD     x4, x1, x8              ;base + 0x2BB8 = base + 0xDDD348 + 0xFFFFFFFFFF225870 
000000A4  03A40817  23(0x17)  --------  STR     x4, [sp, #0x20]         ;vm2_memcpy: base + 0x2BB8
000000A8  00E1230B  11(0x0B)  12(0x0C)  ADD     x4, x1, x7              ;base + 0x2BA8 = base + 0xDDD338 + 0xFFFFFFFFFF225870 
000000AC  03A40617  23(0x17)  --------  STR     x4, [sp, #0x18]         ;vm2_sha512: base + 0x2BA8
000000B0  00A1230B  11(0x0B)  12(0x0C)  ADD     x4, x1, x5              ;base + 0x2B94 = base + 0xDDD324 + 0xFFFFFFFFFF225870 
000000B4  03A40017  23(0x17)  --------  STR     x4, [sp, #0x0]          ;vm2_generate_aes_key_iv: base + 0x2B94
000000B8  8061B30B  11(0x0B)  12(0x0C)  ADD     x23, x1, x3             ;vm2_generate_rand: base + 0x2B5C到x23寄存器，base + 0x2B5C = base + 0xDDD2EC + 0xFFFFFFFFFF225870,
000000BC  0041F30B  11(0x0B)  12(0x0C)  ADD     x30, x1, x2             ;vm2_malloc: base + 0x2B40到x30寄存器，base + 0x2B40 = base + 0xDDD2D0 + 0xFFFFFFFFFF225870
000000C0  00140815  21(0x15)  --------  ADD     x20, x0, #0x20          ;randNumberSize: 0+0x20
000000C4  1BB40C17  23(0x17)  --------  STR     x20, [sp, #0x1b0]       ;arg1: randNumberSize=0x20
000000C8  1BA50C15  21(0x15)  --------  ADD     x5, sp, #0x1b0          ;pArgs: 参数指针8个字节，0x0:pArg保存参数，0x8:pArg+8保存返回值
000000CC  03C021CB  11(0x0B)  07(0x07)  ORR     x4, x0, x30             ;准备跳板目标: base + 0x2B40 = vm2_malloc
000000D0  8200C1CB  11(0x0B)  07(0x07)  ORR     x25, x0, x16            ;跳板函数：pCallRegisterTrampolineFunction
000000D4  03AB0A17  23(0x17)  --------  STR     x11, [sp, #0x28]        ;pDstBuffer
000000DC  03AC0217  23(0x17)  --------  STR     x12, [sp, #0x8]         ;>> pScrBuffer
000000D8  8320FACB  11(0x0B)  43(0x2B)  BR      x25                     ;LR=lr，------> pRandNumber=vm2_malloc(0x20)
000000E0  1BB40A17  23(0x17)  --------  STR     x20, [sp, #0x1a8]       ;arg2: randNumberSize=0x20
000000E4  1BB50E28  40(0x28)  --------  LDR     x21, [sp, #0x1b8]       ;取出返回值 pRandNumber
000000E8  1BB50817  23(0x17)  --------  STR     x21, [sp, #0x1a0]       ;arg1: pRandNumber
000000EC  1BA50815  21(0x15)  --------  ADD     x5, sp, #0x1a0
000000F0  8200C1CB  11(0x0B)  07(0x07)  ORR     x25, x0, x16
000000F8  02E021CB  11(0x0B)  07(0x07)  ORR     x4, x0, x23             ;准备跳板目标
000000F4  8320FACB  11(0x0B)  43(0x2B)  BR      x25                     ;LR=lr, ------> generate_rand(pRandNumber,randNumberSize),生成指定len长度的随机数
000000FC  1BA50415  21(0x15)  --------  ADD     x5, sp, #0x190          ;pArgs: 准备参数指针
00000100  00160415  21(0x15)  --------  ADD     x22, x0, #0x10
00000104  1BB60417  23(0x17)  --------  STR     x22, [sp, #0x190]       ;arg1: aesKeyIVLen=0x10
00000108  8200C1CB  11(0x0B)  07(0x07)  ORR     x25, x0, x16
00000110  03C021CB  11(0x0B)  07(0x07)  ORR     x4, x0, x30             ;准备跳板目标
0000010C  8320FACB  11(0x0B)  43(0x2B)  BR      x25                     ;LR=lr, ------> pAesKey=vm2_malloc(aesKeyIVLen)
00000114  1BA50015  21(0x15)  --------  ADD     x5, sp, #0x180          ;pArgs: 准备参数指针
00000118  1BB60017  23(0x17)  --------  STR     x22, [sp, #0x180]       ;arg1:aesKeyIVLen=0x10
0000011C  1BB10628  40(0x28)  --------  LDR     x17, [sp, #0x198]       ;取出返回值 pAesKey
00000120  03B10417  23(0x17)  --------  STR     x17, [sp, #0x10]        ;保存 pAesKey
00000124  8200C1CB  11(0x0B)  07(0x07)  ORR     x25, x0, x16
0000012C  03C021CB  11(0x0B)  07(0x07)  ORR     x4, x0, x30             ;准备跳板目标
00000128  8320FACB  11(0x0B)  43(0x2B)  BR      x25                     ;LR=lr, ------> pAesIV=vm2_malloc(aesKeyIVLen=0x10)
00000130  17B50417  23(0x17)  --------  STR     x21, [sp, #0x150]       ;arg1: pRandNumber
00000134  17B40617  23(0x17)  --------  STR     x20, [sp, #0x158]       ;arg2: randNumberSize=0x20
00000138  17B10817  23(0x17)  --------  STR     x17, [sp, #0x160]       ;arg3: pAesKey
0000013C  17B60A17  23(0x17)  --------  STR     x22, [sp, #0x168]       ;arg4: aesKeyIVLen=0x10
00000140  17B60E17  23(0x17)  --------  STR     x22, [sp, #0x178]       ;arg6: aesKeyIVLen=0x10
00000144  1BB40228  40(0x28)  --------  LDR     x20, [sp, #0x188]       ;取出返回值 pAesIV
00000148  17B40C17  23(0x17)  --------  STR     x20, [sp, #0x170]       ;arg5: pAesIV
0000014C  03A40028  40(0x28)  --------  LDR     x4, [sp, #0x0]          ;准备跳板目标: 0x2B94
00000150  8200C1CB  11(0x0B)  07(0x07)  ORR     x25, x0, x16
00000158  17A50415  21(0x15)  --------  ADD     x5, sp, #0x150          ;参数指针: args={0x0: pRandNumber, 0x08:randNumberSize=0x20, 0x10:pAesKey, 0x18: aesKeyIVLen=0x10, 0x20:pAesIV, 0x28: aesKeyIVLen=0x10}
00000154  8320FACB  11(0x0B)  43(0x2B)  BR      x25                     ;LR=lr, ------> call vm2_generate_aes_key_iv({0x0: pRandNumber, 0x08:randNumberSize=0x20, 0x10:pAesKey, 0x18: aesKeyIVLen=0x10, 0x20:pAesIV, 0x28: aesKeyIVLen=0x10})
0000015C  06710015  21(0x15)  --------  ADD     x17, x19, #0x40         ;plaintextSize = srcSize + 0x40, 0x40是sha512散列的长度
00000160  17A50015  21(0x15)  --------  ADD     x5, sp, #0x140          ;pArgs
00000164  17B10017  23(0x17)  --------  STR     x17, [sp, #0x140]       ;arg1: plaintextSize
00000168  8200C1CB  11(0x0B)  07(0x07)  ORR     x25, x0, x16
00000170  03C021CB  11(0x0B)  07(0x07)  ORR     x4, x0, x30             ;准备跳板目标: vm2_malloc
0000016C  8320FACB  11(0x0B)  43(0x2B)  BR      x25                     ;LR=lr, ------> pPlaintext=vm2_malloc(plaintextSize)
00000174  07BE0215  21(0x15)  --------  ADD     x30, sp, #0x48          
00000178  17B60228  40(0x28)  --------  LDR     x22, [sp, #0x148]       ;取出返回值 pPlaintext
0000017C  13B30C17  23(0x17)  --------  STR     x19, [sp, #0x130]       ;arg2: srcSize
00000180  03B70228  40(0x28)  --------  LDR     x23, [sp, #0x8]         ;<< pScrBuffer
00000184  13B70A17  23(0x17)  --------  STR     x23, [sp, #0x128]       ;arg1: pScrBuffer
00000188  13BE0E17  23(0x17)  --------  STR     x30, [sp, #0x138]       ;arg3: pSHA512Output
0000018C  03A40628  40(0x28)  --------  LDR     x4, [sp, #0x18]         ;vm2_sha512
00000190  8200C1CB  11(0x0B)  07(0x07)  ORR     x25, x0, x16
00000198  13A50A15  21(0x15)  --------  ADD     x5, sp, #0x128          ;pArgs
00000194  8320FACB  11(0x0B)  43(0x2B)  BR      x25                     ;LR=lr, ------> vm2_sha512(pScrBuffer, srcSize, pSHA512Output)
0000019C  13A50415  21(0x15)  --------  ADD     x5, sp, #0x110          ;pArgs
000001A0  04010015  21(0x15)  --------  ADD     x1, x0, #0x40           ;SHA512OutSize
000001A4  13BE0617  23(0x17)  --------  STR     x30, [sp, #0x118]       ;arg2: pSHA512Output
000001A8  13B60417  23(0x17)  --------  STR     x22, [sp, #0x110]       ;arg1: pPlaintext
000001AC  13A10817  23(0x17)  --------  STR     x1, [sp, #0x120]        ;arg3: SHA512OutSize=0x40
000001B0  03BE0828  40(0x28)  --------  LDR     x30, [sp, #0x20]
000001B4  8200C1CB  11(0x0B)  07(0x07)  ORR     x25, x0, x16
000001BC  03C021CB  11(0x0B)  07(0x07)  ORR     x4, x0, x30             ;vm2_memcpy
000001B8  8320FACB  11(0x0B)  43(0x2B)  BR      x25                     ;LR=lr, ------> vm2_memcpy(pPlaintext, pSHA512Output, SHA512OutSize)
000001C0  0FA50E15  21(0x15)  --------  ADD     x5, sp, #0xf8           ;pArgs
000001C4  06C10015  21(0x15)  --------  ADD     x1, x22, #0x40
000001C8  13B70017  23(0x17)  --------  STR     x23, [sp, #0x100]       ;arg2: pScrBuffer
000001CC  0FA10E17  23(0x17)  --------  STR     x1, [sp, #0xf8]         ;arg1: pDst=pPlaintext+0x40
000001D0  13B30217  23(0x17)  --------  STR     x19, [sp, #0x108]       ;arg3: srcSize
000001D4  8200C1CB  11(0x0B)  07(0x07)  ORR     x25, x0, x16
000001DC  03C021CB  11(0x0B)  07(0x07)  ORR     x4, x0, x30
000001D8  8320FACB  11(0x0B)  43(0x2B)  BR      x25                     ;LR=lr, ------> vm2_memcpy(pDst, pScrBuffer, srcSize), pPlaintext{0x0: sha512, 0x40: srcBuffer}
000001E0  00010811  17(0x11)  --------  ADD     x1, x0, #0x20           ;0 + 0x20
000001E4  0FB50A17  23(0x17)  --------  STR     x21, [sp, #0xe8]        ;arg2: pRandNumber
000001E8  03B30A28  40(0x28)  --------  LDR     x19, [sp, #0x28]
000001EC  0FB30817  23(0x17)  --------  STR     x19, [sp, #0xe0]        ;arg1: pDstBuffer
000001F0  0FA10C30  48(0x30)  --------  STR     w1, [sp, #0xf0]         ;arg3: 0x20
000001F4  03A40C28  40(0x28)  --------  LDR     x4, [sp, #0x30]         ;vm2_memcpy_with_flags
000001F8  8200C1CB  11(0x0B)  07(0x07)  ORR     x25, x0, x16
00000200  0FA50815  21(0x15)  --------  ADD     x5, sp, #0xe0           ;pArgs
000001FC  8320FACB  11(0x0B)  43(0x2B)  BR      x25                     ;LR=lr, ------> vm2_memcpy_with_flags(pDstBuffer, pRandNumber, 0x20), pDstBuffer{0: magic, 0x6: randsNumber}
00000204  02610995  21(0x15)  --------  ADD     x1, x19, #0x26          ;pAesOut = pDstBuffer + 0x26
00000208  03B30428  40(0x28)  --------  LDR     x19, [sp, #0x10]
0000020C  00020411  17(0x11)  --------  ADD     x2, x0, #0x10           ;0 + 0x10
00000210  0BA30215  21(0x15)  --------  ADD     x3, sp, #0x88           ;取一个指针: pAddSubSrcSize
00000214  0BB30A17  23(0x17)  --------  STR     x19, [sp, #0xa8]        ;arg1: pAesKey
00000218  0BA20C30  48(0x30)  --------  STR     w2, [sp, #0xb0]         ;arg2: aesKeyIVLen=0x10
0000021C  0BB40E17  23(0x17)  --------  STR     x20, [sp, #0xb8]        ;arg3: pAesIV
00000220  0FB60017  23(0x17)  --------  STR     x22, [sp, #0xc0]        ;arg4: pPlaintext
00000224  0FB10217  23(0x17)  --------  STR     x17, [sp, #0xc8]        ;arg5: plaintextSize = srcSize + 0x40
00000228  0FA10417  23(0x17)  --------  STR     x1, [sp, #0xd0]         ;arg6: pAesOut = pDstBuffer + 0x26
0000022C  0FA30617  23(0x17)  --------  STR     x3, [sp, #0xd8]         ;arg7: pAddSubSrcSize
00000230  0BA10228  40(0x28)  --------  LDR     x1, [sp, #0x88]         
00000234  FC21F695  21(0x15)  --------  ADD     x1, x1, #-0x26
00000238  0BA10217  23(0x17)  --------  STR     x1, [sp, #0x88]         ;addSubSrcSize = addSrcSize - 0x26
0000023C  03A40E28  40(0x28)  --------  LDR     x4, [sp, #0x38]         ;vm2_aes
00000240  8200C1CB  11(0x0B)  07(0x07)  ORR     x25, x0, x16
00000248  0BA50A15  21(0x15)  --------  ADD     x5, sp, #0xa8           ;pArgs
00000244  8320FACB  11(0x0B)  43(0x2B)  BR      x25                     ;LR=lr, ------> vm2_aes(pAesKey, aesKeyIVLen, pAesIV, pPlaintext, plaintextSize, pAesOut, pAddSubSrcSize)
0000024C  0BA20228  40(0x28)  --------  LDR     x2, [sp, #0x88]         ;addSubSrcSize
00000254  0000064B  11(0x0B)  25(0x19)  NOP                             ;LSL    x0, x0, #0
00000250  00400118  24(0x18)  --------  B.HS    #0x264                  ;x0, x2, $0x10
00000258  00410995  21(0x15)  --------  ADD     x1, x2, #0x26
00000260  02410017  23(0x17)  --------  STR     x1, [x18, #0x0]
0000025C  0800068C  12(0x0C)  --------  B       0x268
00000264  02400017  23(0x17)  --------  STR     x0, [x18, #0x0]
00000268  0BB50817  23(0x17)  --------  STR     x21, [sp, #0xa0]		   ;arg1: pRandNumber
0000026C  0BA50815  21(0x15)  --------  ADD     x5, sp, #0xa0			   ;pArgs
00000270  07B10028  40(0x28)  --------  LDR     x17, [sp, #0x40]		
00000274  8200C1CB  11(0x0B)  07(0x07)  ORR     x25, x0, x16
0000027C  022021CB  11(0x0B)  07(0x07)  ORR     x4, x0, x17				   ;vm2_free
00000278  8320FACB  11(0x0B)  43(0x2B)  BR      x25                     ;LR=lr, ------> vm2_free(pRandNumber)
00000280  0BB30617  23(0x17)  --------  STR     x19, [sp, #0x98]		   ;arg1: pAesKey
00000284  0BA50615  21(0x15)  --------  ADD     x5, sp, #0x98			   ;pArgs
00000288  8200C1CB  11(0x0B)  07(0x07)  ORR     x25, x0, x16
00000290  022021CB  11(0x0B)  07(0x07)  ORR     x4, x0, x17
0000028C  8320FACB  11(0x0B)  43(0x2B)  BR      x25                     ;LR=lr, ------> vm2_free(pAesKey)
00000294  0BA50415  21(0x15)  --------  ADD     x5, sp, #0x90			   ;pArgs
00000298  0BB60417  23(0x17)  --------  STR     x22, [sp, #0x90]		   ;arg1: pPlaintext
0000029C  8200C1CB  11(0x0B)  07(0x07)  ORR     x25, x0, x16
000002A4  022021CB  11(0x0B)  07(0x07)  ORR     x4, x0, x17
000002A0  8320FACB  11(0x0B)  43(0x2B)  BR      x25                     ;LR=lr, ------> vm2_free(pPlaintext)
000002A8  1FB00028  40(0x28)  --------  LDR     x16, [sp, #0x1c0]       ;恢复寄存器环境
000002AC  1FB10228  40(0x28)  --------  LDR     x17, [sp, #0x1c8]
000002B0  1FB20428  40(0x28)  --------  LDR     x18, [sp, #0x1d0]
000002B4  1FB30628  40(0x28)  --------  LDR     x19, [sp, #0x1d8]
000002B8  1FB40828  40(0x28)  --------  LDR     x20, [sp, #0x1e0]
000002BC  1FB50A28  40(0x28)  --------  LDR     x21, [sp, #0x1e8]
000002C0  1FB60C28  40(0x28)  --------  LDR     x22, [sp, #0x1f0]
000002C4  1FB70E28  40(0x28)  --------  LDR     x23, [sp, #0x1f8]
000002C8  23BE0028  40(0x28)  --------  LDR     x30, [sp, #0x200]
000002CC  23BF0228  40(0x28)  --------  LDR     lr, [sp, #0x208]
000002D4  23BD0415  21(0x15)  --------  ADD     sp, sp, #0x210
000002D0  03E00F8B  11(0x0B)  62(0x3E)  ExitVm       0                  ;lr

已知指令统计:
op1: 21                 使用次数: 27
op1: 23                 使用次数: 56
op1: 40                 使用次数: 38
op1: 24                 使用次数: 2
op1: 12                 使用次数: 2
op1: 52                 使用次数: 1
op1: 7                  使用次数: 1
op1: 17                 使用次数: 2
op1: 48                 使用次数: 2
op1: 11 op2: 7          使用次数: 25
op1: 11 op2: 39         使用次数: 1
op1: 11 op2: 25         使用次数: 2
op1: 11 op2: 12         使用次数: 8
op1: 11 op2: 43         使用次数: 14
op1: 11 op2: 62         使用次数: 1