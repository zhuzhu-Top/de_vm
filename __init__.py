from binaryninja import *

from .header_less import print_jump_target
# from .header_less import Arm64RetHook
from .work_flow import cus_workflow
from .user_il import create_user_func


pwf = Workflow().clone("PythonLogWarnWorkflow")
pwf.show_topology()
pwf.register_activity(Activity("PythonLogWarn", action=cus_workflow))
# pwf.insert("core.function.translateTailCalls", ["PythonLogWarn"])
pwf.insert("core.function.generateMediumLevelIL", ["PythonLogWarn"])
pwf.register()


title = "启动自定义workflow"
description = "启动自定义workflow"
properties = f'{{"title" : "{title}", "description" : "{description}", "type" : "boolean", "default" : false}}'
_settings = Settings()
_settings.register_group("zhuzhu", "My Plugin")
_settings.register_setting("zhuzhu.workFlow", properties)

def plugin_main(bv: BinaryView,func):
    # print(bv.arch.regs)
    # print_jump_target(bv)

    create_user_func(bv)
    # if Settings().get_bool("zhuzhu.workFlow"):
    #     _settings.set_bool("zhuzhu.workFlow", False)
    # else:
    #     _settings.set_bool("zhuzhu.workFlow", True)
    # is_enbale_custom_workflow = Settings().get_bool("zhuzhu.workFlow")
    # log_info("zhuzhu.custom_workflow : {}".format(is_enbale_custom_workflow))
    #
    # bv.get_functions_containing(0x9cc7c)[0].reanalyze()
# PluginCommand.register("ROP\\Create ROP Function", "Make some space for your ROP", plugin_main)
PluginCommand.register_for_function("切换workflow状态", "Make some space for your ROP", plugin_main)







