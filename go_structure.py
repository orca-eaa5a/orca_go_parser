from ctypes import *

class ModuleData(Structure):
    pass

class ModuleData64(ModuleData):
    _fields_=[
        ("pPcHeader", c_void_p),
        
        ("pFuncNameTable", c_void_p),
        ("funcNameTableSize", c_uint32),
        ("funcNameTableCapacity", c_uint32),

        ("pCuTable", c_void_p),
        ("cuTableSize", c_uint32),
        ("cuTableCapacity", c_uint32),

        ("pFileTable", c_void_p),
        ("fileTableSize", c_uint32),
        ("fileTableCapacity", c_uint32),

        ("pPcTable", c_void_p),
        ("pcTableSize", c_uint32),
        ("pcTableCapacity", c_uint32),

        ("pPclnTable", c_void_p),
        ("pclnTableSize", c_uint32),
        ("pclnTableCapacity", c_uint32),

        ("pFTable", c_void_p),
        ("fTableSize", c_uint32),
        ("fTableCapacity", c_uint32),

        ("pFindFuncTable", c_void_p),

        ("min_pc", c_uint32),
        ("max_pc", c_uint32),

        ("textSectionRVA", c_void_p),
        ("eTextSectionRVA", c_void_p),

        ("noptrSectionRVA", c_void_p),
        ("eNopterSectionRVA", c_void_p),

        ("dataSectionRVA", c_void_p),
        ("eDataSectionRVA", c_void_p),

        ("bssSectionRVA", c_void_p),
        ("eBssSectionRVA", c_void_p),

        ("noptrBssSectionRVA", c_void_p),
        ("eNoptrBssSectionRVA", c_void_p),

        ("end_addr", c_void_p),
        ("gcData_addr", c_void_p),
        ("gcBss_addr", c_void_p),
        ("types_addr", c_void_p),
        ("eTypes_addr", c_void_p),

        ("textSectionMapAddr", c_void_p),
        ("textSectionMapSize", c_uint32),
        ("textSectionMapCapacity", c_uint32),

        ("typelinkAddr", c_void_p),
        ("typelinkSize", c_uint32),
        ("typelinkCapacity", c_uint32),

        ("iTableLinkAddr", c_void_p),
        ("iTableSize", c_uint32),
        ("iTableCapacity", c_uint32),

        ("pTableAddr", c_void_p),
        ("pTableSize", c_uint32),
        ("pTableCapacity", c_uint32),

        ("pluginNameAddr", c_void_p),
        ("pluginNameLength", c_uint32),

        ("Reserved1",c_void_p),
        ("Reserved2",c_void_p),
        ("Reserved3",c_void_p),
        ("Reserved4",c_void_p),

        ("moduleNameAddr", c_void_p),
        ("pluginNameLength", c_void_p),

        ("Reserved5",c_void_p),
        ("Reserved6",c_void_p),
        ("Reserved7",c_void_p),
        ("Reserved8",c_void_p),

        ("hasMain", c_uint8),

        ("Unknown1",c_void_p),
        ("Unknown2",c_void_p),
        ("Unknown3",c_void_p),
        ("Unknown4",c_void_p),
        ("Unknown5",c_void_p),

        ("next", c_void_p)
    ]

class ModuleData86(ModuleData):
    _fields_=[
        ("pPcHeader", c_uint32),
        
        ("pFuncNameTable", c_uint32),
        ("funcNameTableSize", c_uint32),
        ("funcNameTableCapacity", c_uint32),

        ("pCuTable", c_uint32),
        ("cuTableSize", c_uint32),
        ("cuTableCapacity", c_uint32),

        ("pFileTable", c_uint32),
        ("fileTableSize", c_uint32),
        ("fileTableCapacity", c_uint32),

        ("pPcTable", c_uint32),
        ("pcTableSize", c_uint32),
        ("pcTableCapacity", c_uint32),

        ("pPclnTable", c_uint32),
        ("pclnTableSize", c_uint32),
        ("pclnTableCapacity", c_uint32),

        ("pFTable", c_uint32),
        ("fTableSize", c_uint32),
        ("fTableCapacity", c_uint32),

        ("pFindFuncTable", c_uint32),

        ("min_pc", c_uint32),
        ("max_pc", c_uint32),

        ("textSectionRVA", c_uint32),
        ("eTextSectionRVA", c_uint32),

        ("noptrSectionRVA", c_uint32),
        ("eNopterSectionRVA", c_uint32),

        ("dataSectionRVA", c_uint32),
        ("eDataSectionRVA", c_uint32),

        ("bssSectionRVA", c_uint32),
        ("eBssSectionRVA", c_uint32),

        ("noptrBssSectionRVA", c_uint32),
        ("eNoptrBssSectionRVA", c_uint32),

        ("end_addr", c_uint32),
        ("gcData_addr", c_uint32),
        ("gcBss_addr", c_uint32),
        ("types_addr", c_uint32),
        ("eTypes_addr", c_uint32),

        ("textSectionMapAddr", c_uint32),
        ("textSectionMapSize", c_uint32),
        ("textSectionMapCapacity", c_uint32),

        ("typelinkAddr", c_uint32),
        ("typelinkSize", c_uint32),
        ("typelinkCapacity", c_uint32),

        ("iTableLinkAddr", c_uint32),
        ("iTableSize", c_uint32),
        ("iTableCapacity", c_uint32),

        ("pTableAddr", c_uint32),
        ("pTableSize", c_uint32),
        ("pTableCapacity", c_uint32),

        ("pluginNameAddr", c_uint32),
        ("pluginNameLength", c_uint32),

        ("Reserved1",c_uint32),
        ("Reserved2",c_uint32),
        ("Reserved3",c_uint32),
        ("Reserved4",c_uint32),

        ("moduleNameAddr", c_uint32),
        ("pluginNameLength", c_uint32),

        ("Reserved5",c_uint32),
        ("Reserved6",c_uint32),
        ("Reserved7",c_uint32),
        ("Reserved8",c_uint32),

        ("hasMain", c_uint8),

        ("Unknown1",c_uint32),
        ("Unknown2",c_uint32),
        ("Unknown3",c_uint32),
        ("Unknown4",c_uint32),
        ("Unknown5",c_uint32),

        ("next", c_uint32)
    ]

class PCHeader(Structure):
    _fields_=[
        ("magic", c_uint32),
        ("pad1", c_uint8),
        ("pad2", c_uint8),
        ("minLC", c_uint8),
        ("ptrSize", c_uint8),
        ("nFunc", c_int),
        ("nFiles", c_uint32),
        ("funcNameOffset", c_uint32),
        ("cuOffset", c_uint32),
        ("filetableOffset", c_uint32),
        ("pcTableOffset", c_uint32),
        ("pclnOffset", c_uint32)
    ]

class Func(Structure):
    _fields_=[
        ("entry", c_uint32), # c_void_p
        ("nameoff", c_int32),
        ("args", c_int32),
        ("deferreturn", c_uint32),
        ("pcsp", c_int32),
        ("pcfile", c_int32),
        ("npcdata", c_int32),
        ("func_id", c_uint16), # 2byte array
        ("nFunc_data", c_uint8)
    ]