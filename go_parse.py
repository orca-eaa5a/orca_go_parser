import idautils
import idc
import idaapi

from ctypes import *
import struct
import ctypes
import common
import utils
from go_structure import *

import log

def parse_module_data(pMem):
    mod_data = ModuleData86 # currently, just handle x86 arch bin
    moddata_bin = b""
    sizeOfModData = ctypes.sizeof(mod_data)
    moddata_bin = common.mem_read_bytes(addr=pMem, size=sizeOfModData)
    mod_data_strt = mod_data.from_buffer_copy(moddata_bin)

    return mod_data_strt

# Just support x86 arch 
def check_is_moduledata(addr):
    mod_data = parse_module_data(pMem=addr)
    pPclnTable = mod_data.pPclnTable
    pclnTableFirstEntry = common.mem_read_integer(pPclnTable)
    if pclnTableFirstEntry == mod_data.textSectionRVA:
        return True
    else:
        return False

def find_module_data_bruteforce(start_addr, break_addr, magic):
    module_data_addr = 0
    cur_addr = start_addr
    while cur_addr < break_addr:
        pPcHeader = common.mem_read_integer(addr=cur_addr)
        pcMagic = common.mem_read_integer(addr=pPcHeader)
        if pcMagic == magic:
            if check_is_moduledata(addr=cur_addr):
                module_data_addr = cur_addr
                break
        cur_addr += ctypes.sizeof(c_int32)
    
    return module_data_addr

def find_moduledata():
    pModuleData = 0
    if common.check_is_stripped():
        log._info("binary is not stripped!")
        for addr, name in idautils.Names():
            if name == "runtime.firstmoduledata":
                pModuleData = addr
                break
    else:
        log._info("binary is stripped..")
        log._info("Now find the moduledata by using brute force searching")
        GO1_16_MAGIC = 0xFFFFFFFA # <-- go 1.16 magic
        text_section = common.get_segment_addr_by_name(name=".text")
        rdata_section = common.get_segment_addr_by_name(name=".rdata")
        data_section = common.get_segment_addr_by_name(name=".data")

        sections = [(".text", text_section), (".rdata", rdata_section), (".data", data_section)]

        for sec_name, section_addr in sections:
            cur_addr = section_addr
            next_section_addr = common.get_next_segment_addr(addr=cur_addr)
            pModuleData = find_module_data_bruteforce(start_addr=section_addr, break_addr=next_section_addr, magic=GO1_16_MAGIC)
            if pModuleData != 0:
                log._info("ModuleData Structure locate at [%s] - @0x%x" % (sec_name, pModuleData))
                break
        
        if pModuleData == 0:
            log._error("Cannot find ModuleData Structre in current binary...")
        
        return pModuleData

def parse_pc_header(pMem):
    sizeOfModData = ctypes.sizeof(PCHeader)
    pcheader_bin = common.mem_read_bytes(addr=pMem, size=sizeOfModData)
    pcHeader_strt = PCHeader.from_buffer_copy(pcheader_bin)

    return pcHeader_strt

def parse__func(pMem):
    sizeOf_func = ctypes.sizeof(Func)
    _func_bin = common.mem_read_bytes(addr=pMem, size=sizeOf_func)
    _func_strt = Func.from_buffer_copy(_func_bin)

    return _func_strt

def parse_pclntable(module_data):
    pPcHeader = module_data.pPcHeader
    pc_header = parse_pc_header(pMem=pPcHeader)
    ptrSize = pc_header.ptrSize
    numberOfFuncs = pc_header.nFunc

    log._info("Number of Functions : %d" % numberOfFuncs)
    
    pclntable_start=module_data.pPclnTable
    cur_addr = pclntable_start
    for idx in range(numberOfFuncs):
        cur_addr = pclntable_start + (2 * ptrSize) * idx
        func_rva = common.mem_read_integer(addr=cur_addr, read_size=ptrSize)
        _func_structure_offset = common.mem_read_integer(addr=cur_addr+ptrSize, read_size=ptrSize)
        _func_addr = pclntable_start + _func_structure_offset
        
        if not idc.GetFunctionName(func_rva):
            log._info("Unk Func @0x%x" % func_rva)
            idc.MakeUnkn(func_rva, idc.DOUNK_EXPAND)
            idaapi.autoWait()
            idc.MakeCode(func_rva)
            idaapi.autoWait()
            if idc.MakeFunction(func_rva):
                idaapi.autoWait()
                log._info("Create Func @0x%x" % func_rva)
        
        _func = parse__func(pMem=_func_addr)
        #args=_func.args
        #func_id=_func.args

        func_name_addr = module_data.pFuncNameTable + _func.nameoff
        func_name = idc.GetString(func_name_addr)
        if func_name:
            clean_func_name = utils.clean_function_name(func_name)
            log._info("@0x%x Name : [%s]" % (func_rva, func_name))
            idc.MakeComm(func_rva, "@0x"+str(hex(func_rva))+" entry")
            idaapi.autoWait()
            
            if idc.MakeStr(func_name_addr, func_name_addr+len(func_name)+1):
                idaapi.autoWait()
            else:
                log._error("@0x%x Name : [%s] Failed..." % (func_rva, func_name))
        
        _func_addr = idaapi.get_func(func_rva)
        if _func_addr is not  None:
            if idc.MakeNameEx(_func_addr.startEA, func_name, flags=idaapi.SN_FORCE):
                idaapi.autoWait()
                log._info("@0x%x Name : [%s]" % (func_rva, func_name))
            else:
                log._error("@0x%x Name : [%s] Failed..." % (func_rva, func_name))