import idautils
import idc
import idaapi
import string

import log
idaapi.require("log")

# https://github.com/0xjiayu/go_parser - pclntbl.parse_func_pointer
def parse_func_pointer():
    renamed = 0
    for segea in idautils.Segments():
        for addr in idautils.Functions(segea, idc.SegEnd(segea)):
        #for addr in idautils.Functions(text_seg.startEA, text_seg.endEA):
            name = idc.GetFunctionName(addr)

            # Look at data xrefs to the function - find the pointer that is located in .rodata
            data_ref = idaapi.get_first_dref_to(addr)
            while data_ref != idc.BADADDR:
                if 'rodata' in idc.get_segm_name(data_ref):
                    # Only rename things that are currently listed as an offset; eg. off_9120B0
                    if 'off_' in idc.GetTrueName(data_ref):
                        if idc.MakeNameEx(data_ref, ('%s_ptr' % name), flags=idaapi.SN_FORCE):
                            idaapi.autoWait()
                            renamed += 1
                        else:
                            log._error('Failed to name pointer @ 0x%02x for %s' % (data_ref, name))

                data_ref = idaapi.get_next_dref_to(addr, data_ref)

# https://github.com/0xjiayu/go_parser # common.clean_function_name
def clean_function_name(name_str):
    '''
    Clean generic 'bad' characters
    '''
    name_str = filter(lambda x: x in string.printable, name_str)
    STRIP_CHARS = [ '(', ')', '[', ']', '{', '}', ' ', '"' ]
    REPLACE_CHARS = ['.', '*', '-', ',', ';', ':', '/', '\xb7' ]
    
    for c in STRIP_CHARS:
        name_str = name_str.replace(c, '')

    for c in REPLACE_CHARS:
        name_str = name_str.replace(c, '_')

    return name_str