
这个项目上次 还原 ollvm 基础上改的

有问题提 issue 可以一起交流 vm 的还原(如果有需要的话,正好马上国庆了,可以尝试建个群什么的,然后我开个腾讯会议,讲解下我的代码,大家一起交流对vm的还原)

我保留了探索过程中写的代码,所以会稍微有点乱,只关注被调用的部分就好了
```angular2html

│   angr_tools.py
│   arch_hook.py
│   data.json
│   data.py
│   dec_opcode.py
│   de_br.py
│   dy_code.py
│   graphviz_tools.py
│   header_less.py
│   LICENSE
│   llil.S
│   plugin.json
│   README.md
│   symbolic_.py
│   symbolic_libEncryptor.py
│   symbolic_libEncryptor2.py   本次代码的主要入口
│   symbolic_libEncryptor2_back.py
│   symbolic_libEncryptor2_back2.py
│   test_exe.py
│   triton_test.py
│   user_il.py
│   utils.py
│   VMEngine.py
│   vm_data.json
│   vm_tools.py
│   work_flow.py
│   __init__.py
│
├───doctest-output
│       100_8320FACB.gv
│       100_8320FACB.gv.pdf
│       101_13A50A15.gv
│
├───Vm              利用angr 捕获数据(比较核心)
│   │   BinjaAst.py
│   │   CONSTS.py
│   │   VmExploration.py
│   │   VMGlobalData.py
│   │   VmState.py
│   │   __init__.py


```

