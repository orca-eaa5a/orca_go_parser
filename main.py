import idautils
import idc
import idaapi

import go_parse
import log

idaapi.require("common")
#idaapi.require("strings")
#idaapi.require("pclntbl")
idaapi.require("go_structure")
idaapi.require("go_parse")
idaapi.require("log")
#idaapi.require("types_builder")
#idaapi.require("itab")


def parse():
    pModuleData = go_parse.find_moduledata()
    module_data = go_parse.parse_module_data(pMem=pModuleData)
    go_parse.parse_pclntable(module_data=module_data)
    #go_parse.parse_func(module_data=module_data)
    print("finish!")

parse()