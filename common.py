import idautils
import idc
import idaapi

import string

import log

def mem_read_integer(addr, read_size=4):
    if read_size == 2:
        return idc.Word(addr) % 0xFFFF

    elif read_size == 4: # 32bit Default
        return idc.Dword(addr) & 0xFFFFFFFF
    
    else: # Read Size is 8 Byte (for 64bit)
        return idc.Qword(addr) & 0xFFFFFFFFFFFFFFFF

def mem_read_bytes(addr, size):
    return idc.GetManyBytes(addr, size)

def get_segment_by_name(seg_name):
    seg=None
    seg = idaapi.get_segm_by_name(seg_name)
    if seg:
        return seg
    return None

def get_segment_addr_from_rdata(name):
    for ea, seg_name in idautils.Names():
        if seg_name == name:
            return ea
    return 0

def get_segment_addr_by_name(name):
    seg_start_addr = 0

    ftype = idc.get_inf_attr(idc.INF_FILETYPE)
    if ftype == idc.FT_PE or ftype == idc.FT_EXE or ftype == idc.FT_EXE_OLD:
        seg = get_segment_by_name(name)
    else:
        seg = get_segment_by_name(".noptrdata")
        if seg == None:
            seg = get_segment_by_name("__noptrdata")

    if seg is None:
        # runtime.pclntab in .rdata for newer PE binaries
        seg_start_addr = get_segment_addr_by_name('runtime.noptrdata')
    else:
        seg_start_addr = seg.start_ea

    if seg_start_addr is None:
        seg_start_addr = 0

    return seg_start_addr

def get_next_segment_addr(addr):
    return idaapi.get_next_seg(addr).start_ea

def check_is_stripped():
    # go compiler can remove it's symbol
    # go build -ldflags "-s -w"
    goplt_seg = get_segment_by_name(".go.plt")
    if goplt_seg:
        return True # stripped
    goplt_seg = get_segment_by_name("__go_plt")
    if goplt_seg:
        return True
    return False # not stripped

# Reference go_parser # common.clean_function_name
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