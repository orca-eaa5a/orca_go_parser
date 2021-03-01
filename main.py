import idautils
import idc
import idaapi

import go_parse
import log
import utils

idaapi.require("common")
idaapi.require("go_structure")
idaapi.require("go_parse")
idaapi.require("log")
idaapi.require("utils")


def parse():
    pModuleData = go_parse.find_moduledata()
    module_data = go_parse.parse_module_data(pMem=pModuleData)
    go_parse.parse_pclntable(module_data=module_data)
    utils.parse_func_pointer()

    print("finish!")

parse()