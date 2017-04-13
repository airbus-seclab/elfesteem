"""Constants and structures associated to Minidump format
Based on: http://amnesia.gtisc.gatech.edu/~moyix/minidump.py
"""
from elfesteem.new_cstruct import CStruct

class Enumeration(object):
    """Stand for an enumeration type"""

    def __init__(self, enum_info):
        """enum_info: {name: value}"""
        self._enum_info = enum_info
        self._inv_info = {}
        for k, v in enum_info.items():
            self._inv_info[v] = k

    def __getitem__(self, key):
        """Helper: assume that string is for key, integer is for value"""
        if key in self._inv_info:
            return self._inv_info[key]
        return self._enum_info[key]

    def __getattr__(self, key):
        if key in self._enum_info:
            return self._enum_info[key]
        raise AttributeError

    def from_value(self, value):
        return self._inv_info[value]


class Rva(CStruct):
    """Relative Virtual Address
    Note: RVA in Minidump means "file offset"
    """
    _fields = [("rva", "u32"),
    ]


minidumpType = Enumeration({
    # MINIDUMP_TYPE
    # https://msdn.microsoft.com/en-us/library/ms680519(v=vs.85).aspx
    "MiniDumpNormal"                          : 0x00000000,
    "MiniDumpWithDataSegs"                    : 0x00000001,
    "MiniDumpWithFullMemory"                  : 0x00000002,
    "MiniDumpWithHandleData"                  : 0x00000004,
    "MiniDumpFilterMemory"                    : 0x00000008,
    "MiniDumpScanMemory"                      : 0x00000010,
    "MiniDumpWithUnloadedModules"             : 0x00000020,
    "MiniDumpWithIndirectlyReferencedMemory"  : 0x00000040,
    "MiniDumpFilterModulePaths"               : 0x00000080,
    "MiniDumpWithProcessThreadData"           : 0x00000100,
    "MiniDumpWithPrivateReadWriteMemory"      : 0x00000200,
    "MiniDumpWithoutOptionalData"             : 0x00000400,
    "MiniDumpWithFullMemoryInfo"              : 0x00000800,
    "MiniDumpWithThreadInfo"                  : 0x00001000,
    "MiniDumpWithCodeSegs"                    : 0x00002000,
    "MiniDumpWithoutAuxiliaryState"           : 0x00004000,
    "MiniDumpWithFullAuxiliaryState"          : 0x00008000,
    "MiniDumpWithPrivateWriteCopyMemory"      : 0x00010000,
    "MiniDumpIgnoreInaccessibleMemory"        : 0x00020000,
    "MiniDumpWithTokenInformation"            : 0x00040000,
    "MiniDumpWithModuleHeaders"               : 0x00080000,
    "MiniDumpFilterTriage"                    : 0x00100000,
    "MiniDumpValidTypeFlags"                  : 0x001fffff,
})

def time_str(value, zero=False):
    if zero and value == 0: return '0'
    import time
    return '%#x %s' % (value,
               time.strftime('%Y-%m-%d %H:%M:%S',
               time.gmtime(value))),

def data_str(v):
    import struct
    return '0x' + ''.join(["%02x"%_ for _ in struct.unpack("%dB"%len(v), v)])

class MinidumpHDR(CStruct):
    """MINIDUMP_HEADER
    https://msdn.microsoft.com/en-us/library/ms680378(VS.85).aspx
    """
    _fields = [("Magic", "u32"), # MDMP
               ("Version", "u16"),
               ("ImplementationVersion", "u16"),
               ("NumberOfStreams", "u32"),
               ("StreamDirectoryRva", "Rva"),
               ("Checksum", "u32"),
               ("TimeDateStamp", "u32"),
               ("Flags", "u32")
    ]
    def dump(self):
        return '\n'.join([
            'MDRawHeader',
            '  signature            = %#x' % self.Magic,
            '  version              = %#x' % (self.Version+(self.ImplementationVersion<<16)),
            '  stream_count         = %d' % self.NumberOfStreams,
            '  stream_directory_rva = %#x' % self.StreamDirectoryRva.rva,
            '  checksum             = %#x' % self.Checksum,
            '  time_date_stamp      = %s' % time_str(self.TimeDateStamp),
            '  flags                = %#x' % self.Flags,
            ])

class LocationDescriptor(CStruct):
    """MINIDUMP_LOCATION_DESCRIPTOR
    https://msdn.microsoft.com/en-us/library/ms680383(v=vs.85).aspx
    """
    _fields = [("DataSize", "u32"),
               ("Rva", "Rva"),
    ]


streamType = Enumeration({
    # MINIDUMP_STREAM_TYPE
    # https://msdn.microsoft.com/en-us/library/ms680394(v=vs.85).aspx
    "UnusedStream"               : 0,
    "ReservedStream0"            : 1,
    "ReservedStream1"            : 2,
    "ThreadListStream"           : 3,
    "ModuleListStream"           : 4,
    "MemoryListStream"           : 5,
    "ExceptionStream"            : 6,
    "SystemInfoStream"           : 7,
    "ThreadExListStream"         : 8,
    "Memory64ListStream"         : 9,
    "CommentStreamA"             : 10,
    "CommentStreamW"             : 11,
    "HandleDataStream"           : 12,
    "FunctionTableStream"        : 13,
    "UnloadedModuleListStream"   : 14,
    "MiscInfoStream"             : 15,
    "MemoryInfoListStream"       : 16,
    "ThreadInfoListStream"       : 17,
    "HandleOperationListStream"  : 18,
    "LastReservedStream"         : 0xffff,
})

MDminidumpType = Enumeration({
    # MINIDUMP_STREAM_TYPE
    # https://chromium.googlesource.com/breakpad/breakpad/+/master/src/google_breakpad/common/minidump_format.h
    "MD_UNUSED_STREAM"               :  0,
    "MD_RESERVED_STREAM_0"           :  1,
    "MD_RESERVED_STREAM_1"           :  2,
    "MD_THREAD_LIST_STREAM"          :  3, # MDRawThreadList
    "MD_MODULE_LIST_STREAM"          :  4, # MDRawModuleList
    "MD_MEMORY_LIST_STREAM"          :  5, # MDRawMemoryList
    "MD_EXCEPTION_STREAM"            :  6, # MDRawExceptionStream
    "MD_SYSTEM_INFO_STREAM"          :  7, # MDRawSystemInfo
    "MD_THREAD_EX_LIST_STREAM"       :  8,
    "MD_MEMORY_64_LIST_STREAM"       :  9,
    "MD_COMMENT_STREAM_A"            : 10,
    "MD_COMMENT_STREAM_W"            : 11,
    "MD_HANDLE_DATA_STREAM"          : 12,
    "MD_FUNCTION_TABLE_STREAM"       : 13,
    "MD_UNLOADED_MODULE_LIST_STREAM" : 14,
    "MD_MISC_INFO_STREAM"            : 15, # MDRawMiscInfo
    "MD_MEMORY_INFO_LIST_STREAM"     : 16, # MDRawMemoryInfoList
    "MD_THREAD_INFO_LIST_STREAM"     : 17,
    "MD_HANDLE_OPERATION_LIST_STREAM" : 18,
    "MD_TOKEN_STREAM"                : 19,
    "MD_JAVASCRIPT_DATA_STREAM"      : 20,
    "MD_SYSTEM_MEMORY_INFO_STREAM"   : 21,
    "MD_PROCESS_VM_COUNTERS_STREAM"  : 22,
    "MD_LAST_RESERVED_STREAM"        : 0x0000ffff,
    # Breakpad extension types.  0x4767 = "Gg"
    "MD_BREAKPAD_INFO_STREAM"        : 0x47670001,  # MDRawBreakpadInfo
    "MD_ASSERTION_INFO_STREAM"       : 0x47670002,  # MDRawAssertionInfo
    # These are additional minidump stream values which are specific to
    # the linux breakpad implementation.
    "MD_LINUX_CPU_INFO"              : 0x47670003,  # /proc/cpuinfo
    "MD_LINUX_PROC_STATUS"           : 0x47670004,  # /proc/$x/status
    "MD_LINUX_LSB_RELEASE"           : 0x47670005,  # /etc/lsb-release
    "MD_LINUX_CMD_LINE"              : 0x47670006,  # /proc/$x/cmdline
    "MD_LINUX_ENVIRON"               : 0x47670007,  # /proc/$x/environ
    "MD_LINUX_AUXV"                  : 0x47670008,  # /proc/$x/auxv
    "MD_LINUX_MAPS"                  : 0x47670009,  # /proc/$x/maps
    "MD_LINUX_DSO_DEBUG"             : 0x4767000A,  # MDRawDebug{32,64}
})


class StreamDirectory(CStruct):
    """MINIDUMP_DIRECTORY
    https://msdn.microsoft.com/en-us/library/ms680365(VS.85).aspx
    """
    _fields = [("StreamType", "u32"),
               ("Location", "LocationDescriptor"),
    ]

    @property
    def pretty_name(self):
        return streamType[self.StreamType]

    @property
    def type_with_name(self):
        return "%#x (%s)" % (self.StreamType,
                MDminidumpType.from_value(self.StreamType) )

    def dump(self):
        return '\n'.join([
            'MDRawDirectory',
            '  stream_type        = %s' % self.type_with_name,
            '  location.data_size = %d' % self.Location.DataSize,
            '  location.rva       = %#x' % self.Location.Rva.rva,
            ])

MD_VSFIXEDFILEINFO_SIGNATURE = 0xfeef04bd
MD_VSFIXEDFILEINFO_VERSION   = 0x00010000
class FixedFileInfo(CStruct):
    """VS_FIXEDFILEINFO
    https://msdn.microsoft.com/en-us/library/ms646997(v=vs.85).aspx
    """
    _fields = [("dwSignature", "u32"),
               ("dwStrucVersion", "u32"),
               ("dwFileVersionMS", "u32"),
               ("dwFileVersionLS", "u32"),
               ("dwProductVersionMS", "u32"),
               ("dwProductVersionLS", "u32"),
               ("dwFileFlagsMask", "u32"),
               ("dwFileFlags", "u32"),
               ("dwFileOS", "u32"),
               ("dwFileType", "u32"),
               ("dwFileSubtype", "u32"),
               ("dwFileDateMS", "u32"),
               ("dwFileDateLS", "u32"),
    ]
    @property
    def version(self):
        if self.dwSignature != MD_VSFIXEDFILEINFO_SIGNATURE:
            return ''
        if not (self.dwStrucVersion & MD_VSFIXEDFILEINFO_VERSION):
            return ''
        return '%d.%d.%d.%d' % (
                self.dwFileVersionMS>>16,
                self.dwFileVersionMS&0xffff,
                self.dwFileVersionLS>>16,
                self.dwFileVersionLS&0xffff)

class MinidumpString(CStruct):
    """MINIDUMP_STRING
    https://msdn.microsoft.com/en-us/library/ms680395(v=vs.85).aspx
    """
    _fields = [("Length", "u32"),
               ("Buffer", "u08", lambda string:string.Length),
    ]
    def __str__(self):
        import struct
        return struct.pack("%dB"%len(self.Buffer), *self.Buffer).decode("utf-16")

class CvRecord(CStruct):
    _fields = [("CvSignature", "u32"),
               ("Sign0", "u32"),
               ("Sign1", "u16"),
               ("Sign2", "u16"),
               ("SignX", "u08", lambda _: 8),
               ("Age", "u32"),
    ]
    @property
    def signature_str(self):
        return '%08x-%04x-%04x-' % (self.Sign0, self.Sign1, self.Sign2) \
             + ('%02x%02x-'+'%02x'*6) % tuple(self.SignX)
    @property
    def signature_id(self):
        return '%08X%04X%04X' % (self.Sign0, self.Sign1, self.Sign2) \
             + ('%02X'*8) % tuple(self.SignX)

class Module(CStruct):
    """MINIDUMP_MODULE
    https://msdn.microsoft.com/en-us/library/ms680392(v=vs.85).aspx
    """
    _fields = [("BaseOfImage", "u64"),
               ("SizeOfImage", "u32"),
               ("CheckSum", "u32"),
               ("TimeDateStamp", "u32"),
               ("ModuleNameRva", "Rva"),
               ("VersionInfo", "FixedFileInfo"),
               ("CvRecord", "LocationDescriptor"),
               ("MiscRecord", "LocationDescriptor"),
               ("Reserved0", "u64"),
               ("Reserved1", "u64"),
    ]

    def parse_data(self):
        self.cv = CvRecord.unpack(self.parent_head._content,
                             off = self.CvRecord.Rva.rva,
                             parent_head = self.parent_head)
        self.cv.filename = self.parent_head._content[self.CvRecord.Rva.rva+24:self.CvRecord.Rva.rva+self.CvRecord.DataSize-1].decode('latin1') # last character is NULL
        rva = self.MiscRecord.Rva.rva
        if rva == 0: self.misc_record = '(null)'

    @property
    def ModuleName(self):
        return MinidumpString.unpack(self.parent_head._content,
                                     off = self.ModuleNameRva.rva,
                                     parent_head = self.parent_head)

    def dump(self):
        return '\n'.join([
            'MDRawModule',
            '  base_of_image                   = %#x' % self.BaseOfImage,
            '  size_of_image                   = %#x' % self.SizeOfImage,
            '  checksum                        = %#x' % self.CheckSum,
            '  time_date_stamp                 = %s' % time_str(self.TimeDateStamp),
            '  module_name_rva                 = %#x' % self.ModuleNameRva.rva,
            '  version_info.signature          = %#x' % self.VersionInfo.dwSignature,
            '  version_info.struct_version     = %#x' % self.VersionInfo.dwStrucVersion,
            '  version_info.file_version       = %#x:%#x' % (self.VersionInfo.dwFileVersionMS, self.VersionInfo.dwFileVersionLS),
            '  version_info.product_version    = %#x:%#x' % (self.VersionInfo.dwProductVersionMS, self.VersionInfo.dwProductVersionLS),
            '  version_info.file_flags_mask    = %#x' % self.VersionInfo.dwFileFlagsMask,
            '  version_info.file_flags         = %#x' % self.VersionInfo.dwFileFlags,
            '  version_info.file_os            = %#x' % self.VersionInfo.dwFileOS,
            '  version_info.file_type          = %#x' % self.VersionInfo.dwFileType,
            '  version_info.file_subtype       = %#x' % self.VersionInfo.dwFileSubtype,
            '  version_info.file_date          = %#x:%#x' % (self.VersionInfo.dwFileDateMS, self.VersionInfo.dwFileDateLS),
            '  cv_record.data_size             = %d' % self.CvRecord.DataSize,
            '  cv_record.rva                   = %#x' % self.CvRecord.Rva.rva,
            '  misc_record.data_size           = %d' % self.MiscRecord.DataSize,
            '  misc_record.rva                 = %#x' % self.MiscRecord.Rva.rva,
            ])

    def dump_other(self):
        self.parse_data()
        if self.parent_head.systeminfo.PlatformId in (
                MD_OS_WIN32_NT,
                MD_OS_WIN32_WINDOWS,
                ):
            code_identifier = "%X%x" % (self.TimeDateStamp, self.SizeOfImage)
        elif self.parent_head.systeminfo.PlatformId in (
                MD_OS_ANDROID,
                MD_OS_LINUX,
                MD_OS_MAC_OS_X,
                MD_OS_IOS,
                MD_OS_SOLARIS,
                MD_OS_NACL,
                MD_OS_PS3,
                ):
            code_identifier = "id"
        debug_identifier = self.cv.signature_id + '%d'%self.cv.Age
        return '\n'.join([
            '  (code_file)                     = "%s"' % self.ModuleName,
            '  (code_identifier)               = "%s"' % code_identifier,
            '  (cv_record).cv_signature        = %#x' % self.cv.CvSignature,
            '  (cv_record).signature           = %s' % self.cv.signature_str,
            '  (cv_record).age                 = %d' % self.cv.Age,
            '  (cv_record).pdb_file_name       = "%s"' % self.cv.filename,
            '  (misc_record)                   = %s' % self.misc_record,
            '  (debug_file)                    = "%s"' % self.cv.filename,
            '  (debug_identifier)              = "%s"' % debug_identifier,
            '  (version)                       = "%s"' % self.VersionInfo.version,
            ])



class ModuleList(CStruct):
    """MINIDUMP_MODULE_LIST
    https://msdn.microsoft.com/en-us/library/ms680391(v=vs.85).aspx
    """
    _fields = [("NumberOfModules", "u32"),
               ("Modules", "Module", lambda mlist:mlist.NumberOfModules),
    ]

class ModuleListWithPadding(CStruct):
    """MINIDUMP_THREAD_LIST may have 4 bytes padding
    https://chromium.googlesource.com/breakpad/breakpad/+/master/src/processor/minidump.cc
    cf. function MinidumpModuleList::Read
    """
    _fields = [("NumberOfModules", "u32"),
               ("Padding", "u32"),
               ("Modules", "Module", lambda mlist:mlist.NumberOfModules),
    ]


class MemoryDescriptor64(CStruct):
    """MINIDUMP_MEMORY_DESCRIPTOR64
    https://msdn.microsoft.com/en-us/library/ms680384(v=vs.85).aspx
    """
    _fields = [("StartOfMemoryRange", "u64"),
               ("DataSize", "u64")
    ]


class Memory64List(CStruct):
    """MINIDUMP_MEMORY64_LIST
    https://msdn.microsoft.com/en-us/library/ms680387(v=vs.85).aspx
    """
    _fields = [("NumberOfMemoryRanges", "u64"),
               ("BaseRva", "u64"),
               ("MemoryRanges", "MemoryDescriptor64",
                lambda mlist:mlist.NumberOfMemoryRanges),
    ]

class MemoryDescriptor(CStruct):
    """MINIDUMP_MEMORY_DESCRIPTOR
    https://msdn.microsoft.com/en-us/library/ms680384(v=vs.85).aspx
    """
    _fields = [("StartOfMemoryRange", "u64"),
               ("Memory", "LocationDescriptor"),
    ]
    def dump(self):
        return '\n'.join([
            'MDMemoryDescriptor',
            '  start_of_memory_range = %#x' % self.StartOfMemoryRange,
            '  memory.data_size      = %#x' % self.Memory.DataSize,
            '  memory.rva            = %#x' % self.Memory.Rva.rva,
            ])

class MemoryList(CStruct):
    """MINIDUMP_MEMORY_LIST
    https://msdn.microsoft.com/en-us/library/ms680387(v=vs.85).aspx
    """
    _fields = [("NumberOfMemoryRanges", "u32"),
               ("MemoryRanges", "MemoryDescriptor",
                lambda mlist:mlist.NumberOfMemoryRanges),
    ]

class MemoryListWithPadding(CStruct):
    _fields = [("NumberOfMemoryRanges", "u32"),
               ("Padding", "u32"),
               ("MemoryRanges", "MemoryDescriptor",
                lambda mlist:mlist.NumberOfMemoryRanges),
    ]

memProtect = Enumeration({
    # MEM PROTECT
    # https://msdn.microsoft.com/en-us/library/aa366786(v=vs.85).aspx
    "PAGE_NOACCESS"          : 0x0001,
    "PAGE_READONLY"          : 0x0002,
    "PAGE_READWRITE"         : 0x0004,
    "PAGE_WRITECOPY"         : 0x0008,
    "PAGE_EXECUTE"           : 0x0010,
    "PAGE_EXECUTE_READ"      : 0x0020,
    "PAGE_EXECUTE_READWRITE" : 0x0040,
    "PAGE_EXECUTE_WRITECOPY" : 0x0080,
    "PAGE_GUARD"             : 0x0100,
    "PAGE_NOCACHE"           : 0x0200,
    "PAGE_WRITECOMBINE"      : 0x0400,
})

class MemoryInfo(CStruct):
    """MINIDUMP_MEMORY_INFO
    https://msdn.microsoft.com/en-us/library/ms680386(v=vs.85).aspx
    """
    _fields = [("BaseAddress", "u64"),
               ("AllocationBase", "u64"),
               ("AllocationProtect", "u32"),
               ("__alignment1", "u32"),
               ("RegionSize", "u64"),
               ("State", "u32"),
               ("Protect", "u32"),
               ("Type", "u32"),
               ("__alignment2", "u32"),
    ]

class MemoryInfoList(CStruct):
    """MINIDUMP_MEMORY_INFO_LIST
    https://msdn.microsoft.com/en-us/library/ms680385(v=vs.85).aspx
    """
    _fields = [("SizeOfHeader", "u32"),
               ("SizeOfEntry", "u32"),
               ("NumberOfEntries", "u64"),
                # Fake field, for easy access to MemoryInfo elements
               ("MemoryInfos", "MemoryInfo",
                lambda mlist: mlist.NumberOfEntries),
    ]


contextFlags_x86 = Enumeration({
    "CONTEXT_i386"                : 0x00010000,
    "CONTEXT_CONTROL"             : 0x00010001,
    "CONTEXT_INTEGER"             : 0x00010002,
    "CONTEXT_SEGMENTS"            : 0x00010004,
    "CONTEXT_FLOATING_POINT"      : 0x00010008,
    "CONTEXT_DEBUG_REGISTERS"     : 0x00010010,
    "CONTEXT_EXTENDED_REGISTERS"  : 0x00010020,
})

class FloatingSaveArea(CStruct):
    """FLOATING_SAVE_AREA
    http://terminus.rewolf.pl/terminus/structures/ntdll/_FLOATING_SAVE_AREA_x86.html
    """
    _fields = [("ControlWord", "u32"),
               ("StatusWord", "u32"),
               ("TagWord", "u32"),
               ("ErrorOffset", "u32"),
               ("ErrorSelector", "u32"),
               ("DataOffset", "u32"),
               ("DataSelector", "u32"),
               ("RegisterArea", "80s"),
               ("Cr0NpxState", "u32"),
    ]

class Context_x86(CStruct):
    """CONTEXT x86
    https://msdn.microsoft.com/en-us/en-en/library/ms679284(v=vs.85).aspx
    http://terminus.rewolf.pl/terminus/structures/ntdll/_CONTEXT_x86.html
    """

    MAXIMUM_SUPPORTED_EXTENSION = 512

    def is_activated(flag):
        mask = contextFlags_x86[flag]
        def check_context(ctx):
            return 1
            if (ctx.ContextFlags & mask == mask):
                return 1
            return 0
        return check_context

    _fields = [("ContextFlags", "u32"),
               # DebugRegisters
               ("Dr0", "u32", is_activated("CONTEXT_DEBUG_REGISTERS")),
               ("Dr1", "u32", is_activated("CONTEXT_DEBUG_REGISTERS")),
               ("Dr2", "u32", is_activated("CONTEXT_DEBUG_REGISTERS")),
               ("Dr3", "u32", is_activated("CONTEXT_DEBUG_REGISTERS")),
               ("Dr6", "u32", is_activated("CONTEXT_DEBUG_REGISTERS")),
               ("Dr7", "u32", is_activated("CONTEXT_DEBUG_REGISTERS")),

               ("FloatSave", "FloatingSaveArea",
                is_activated("CONTEXT_FLOATING_POINT")),

               # SegmentRegisters
               ("SegGs", "u32", is_activated("CONTEXT_SEGMENTS")),
               ("SegFs", "u32", is_activated("CONTEXT_SEGMENTS")),
               ("SegEs", "u32", is_activated("CONTEXT_SEGMENTS")),
               ("SegDs", "u32", is_activated("CONTEXT_SEGMENTS")),
               # IntegerRegisters
               ("Edi", "u32", is_activated("CONTEXT_INTEGER")),
               ("Esi", "u32", is_activated("CONTEXT_INTEGER")),
               ("Ebx", "u32", is_activated("CONTEXT_INTEGER")),
               ("Edx", "u32", is_activated("CONTEXT_INTEGER")),
               ("Ecx", "u32", is_activated("CONTEXT_INTEGER")),
               ("Eax", "u32", is_activated("CONTEXT_INTEGER")),
               # ControlRegisters
               ("Ebp", "u32", is_activated("CONTEXT_CONTROL")),
               ("Eip", "u32", is_activated("CONTEXT_CONTROL")),
               ("SegCs", "u32", is_activated("CONTEXT_CONTROL")),
               ("EFlags", "u32", is_activated("CONTEXT_CONTROL")),
               ("Esp", "u32", is_activated("CONTEXT_CONTROL")),
               ("SegSs", "u32", is_activated("CONTEXT_CONTROL")),

               ("ExtendedRegisters", "%ds" % MAXIMUM_SUPPORTED_EXTENSION,
                is_activated("CONTEXT_EXTENDED_REGISTERS")),
    ]
    def dump(self):
        return '\n'.join([
            'MDRawContextX86',
            '  context_flags                = %#x' % self.ContextFlags,
            '  dr0                          = %#x' % self.Dr0[0],
            '  dr1                          = %#x' % self.Dr1[0],
            '  dr2                          = %#x' % self.Dr2[0],
            '  dr3                          = %#x' % self.Dr3[0],
            '  dr6                          = %#x' % self.Dr6[0],
            '  dr7                          = %#x' % self.Dr7[0],
            '  float_save.control_word      = %#x' % self.FloatSave[0].ControlWord,
            '  float_save.status_word       = %#x' % self.FloatSave[0].StatusWord,
            '  float_save.tag_word          = %#x' % self.FloatSave[0].TagWord,
            '  float_save.error_offset      = %#x' % self.FloatSave[0].ErrorOffset,
            '  float_save.error_selector    = %#x' % self.FloatSave[0].ErrorSelector,
            '  float_save.data_offset       = %#x' % self.FloatSave[0].DataOffset,
            '  float_save.data_selector     = %#x' % self.FloatSave[0].DataSelector,
            '  float_save.register_area[80] = %s' % data_str(self.FloatSave[0].RegisterArea),
            '  float_save.cr0_npx_state     = %#x' % self.FloatSave[0].Cr0NpxState,
            '  gs                           = %#x' % self.SegGs[0],
            '  fs                           = %#x' % self.SegFs[0],
            '  es                           = %#x' % self.SegEs[0],
            '  ds                           = %#x' % self.SegDs[0],
            '  edi                          = %#x' % self.Edi[0],
            '  esi                          = %#x' % self.Esi[0],
            '  ebx                          = %#x' % self.Ebx[0],
            '  edx                          = %#x' % self.Edx[0],
            '  ecx                          = %#x' % self.Ecx[0],
            '  eax                          = %#x' % self.Eax[0],
            '  ebp                          = %#x' % self.Ebp[0],
            '  eip                          = %#x' % self.Eip[0],
            '  cs                           = %#x' % self.SegCs[0],
            '  eflags                       = %#x' % self.EFlags[0],
            '  esp                          = %#x' % self.Esp[0],
            '  ss                           = %#x' % self.SegSs[0],
            '  extended_registers[512]      = %s' % data_str(self.ExtendedRegisters[0]),
            ])


contextFlags_AMD64 = Enumeration({
    "CONTEXT_AMD64"               : 0x00100000,
    "CONTEXT_CONTROL"             : 0x00100001,
    "CONTEXT_INTEGER"             : 0x00100002,
    "CONTEXT_SEGMENTS"            : 0x00100004,
    "CONTEXT_FLOATING_POINT"      : 0x00100008,
    "CONTEXT_DEBUG_REGISTERS"     : 0x00100010,
    "CONTEXT_XSTATE"              : 0x00100020,
    "CONTEXT_EXCEPTION_ACTIVE"    : 0x08000000,
    "CONTEXT_SERVICE_ACTIVE"      : 0x10000000,
    "CONTEXT_EXCEPTION_REQUEST"   : 0x40000000,
    "CONTEXT_EXCEPTION_REPORTING" : 0x80000000,
})


class M128A(CStruct):
    """M128A
    http://terminus.rewolf.pl/terminus/structures/ntdll/_M128A_x64.html
    """
    _fields = [("Low", "u64"),
               ("High", "u64"),
    ]

class Context_AMD64(CStruct):
    """CONTEXT AMD64
    https://github.com/duarten/Threadjack/blob/master/WinNT.h
    """

    def is_activated(flag):
        mask = contextFlags_AMD64[flag]
        def check_context(ctx):
            return 1
            if (ctx.ContextFlags & mask == mask):
                return 1
            return 0
        return check_context

    _fields = [

        # Only used for Convenience
        ("P1Home", "u64"),
        ("P2Home", "u64"),
        ("P3Home", "u64"),
        ("P4Home", "u64"),
        ("P5Home", "u64"),
        ("P6Home", "u64"),

        # Control
        ("ContextFlags", "u32"),
        ("MxCsr", "u32"),

        # Segment & processor
        # /!\ activation depends on multiple flags
        ("SegCs", "u16", is_activated("CONTEXT_CONTROL")),
        ("SegDs", "u16", is_activated("CONTEXT_SEGMENTS")),
        ("SegEs", "u16", is_activated("CONTEXT_SEGMENTS")),
        ("SegFs", "u16", is_activated("CONTEXT_SEGMENTS")),
        ("SegGs", "u16", is_activated("CONTEXT_SEGMENTS")),
        ("SegSs", "u16", is_activated("CONTEXT_CONTROL")),
        ("EFlags", "u32", is_activated("CONTEXT_CONTROL")),

        # Debug registers
        ("Dr0", "u64", is_activated("CONTEXT_DEBUG_REGISTERS")),
        ("Dr1", "u64", is_activated("CONTEXT_DEBUG_REGISTERS")),
        ("Dr2", "u64", is_activated("CONTEXT_DEBUG_REGISTERS")),
        ("Dr3", "u64", is_activated("CONTEXT_DEBUG_REGISTERS")),
        ("Dr6", "u64", is_activated("CONTEXT_DEBUG_REGISTERS")),
        ("Dr7", "u64", is_activated("CONTEXT_DEBUG_REGISTERS")),

        # Integer registers
        # /!\ activation depends on multiple flags
        ("Rax", "u64", is_activated("CONTEXT_INTEGER")),
        ("Rcx", "u64", is_activated("CONTEXT_INTEGER")),
        ("Rdx", "u64", is_activated("CONTEXT_INTEGER")),
        ("Rbx", "u64", is_activated("CONTEXT_INTEGER")),
        ("Rsp", "u64", is_activated("CONTEXT_CONTROL")),
        ("Rbp", "u64", is_activated("CONTEXT_INTEGER")),
        ("Rsi", "u64", is_activated("CONTEXT_INTEGER")),
        ("Rdi", "u64", is_activated("CONTEXT_INTEGER")),
        ("R8", "u64", is_activated("CONTEXT_INTEGER")),
        ("R9", "u64", is_activated("CONTEXT_INTEGER")),
        ("R10", "u64", is_activated("CONTEXT_INTEGER")),
        ("R11", "u64", is_activated("CONTEXT_INTEGER")),
        ("R12", "u64", is_activated("CONTEXT_INTEGER")),
        ("R13", "u64", is_activated("CONTEXT_INTEGER")),
        ("R14", "u64", is_activated("CONTEXT_INTEGER")),
        ("R15", "u64", is_activated("CONTEXT_INTEGER")),
        ("Rip", "u64", is_activated("CONTEXT_CONTROL")),

        # Floating point
        ("Header", "M128A", lambda ctx: 2),
        ("Legacy", "M128A", lambda ctx: 8),
        ("Xmm0", "M128A"),
        ("Xmm1", "M128A"),
        ("Xmm2", "M128A"),
        ("Xmm3", "M128A"),
        ("Xmm4", "M128A"),
        ("Xmm5", "M128A"),
        ("Xmm6", "M128A"),
        ("Xmm7", "M128A"),
        ("Xmm8", "M128A"),
        ("Xmm9", "M128A"),
        ("Xmm10", "M128A"),
        ("Xmm11", "M128A"),
        ("Xmm12", "M128A"),
        ("Xmm13", "M128A"),
        ("Xmm14", "M128A"),
        ("Xmm15", "M128A"),


        # Vector registers
        ("VectorRegister", "M128A", lambda ctx: 16),
        ("VectorControl", "u64"),

        # Special debug control regs
        ("DebugControl", "u64"),
        ("LastBranchToRip", "u64"),
        ("LastBranchFromRip", "u64"),
        ("LastExceptionToRip", "u64"),
        ("LastExceptionFromRip", "u64"),
    ]
    def dump(self):
        return '\n'.join([
            'MDRawContextAMD64',
            '  p1_home       = %#x' % self.P1Home,
            '  p2_home       = %#x' % self.P2Home,
            '  p3_home       = %#x' % self.P3Home,
            '  p4_home       = %#x' % self.P4Home,
            '  p5_home       = %#x' % self.P5Home,
            '  p6_home       = %#x' % self.P6Home,
            '  context_flags = %#x' % self.ContextFlags,
            '  mx_csr        = %#x' % self.MxCsr,
            '  cs            = %#x' % self.SegCs[0],
            '  ds            = %#x' % self.SegDs[0],
            '  es            = %#x' % self.SegEs[0],
            '  fs            = %#x' % self.SegFs[0],
            '  gs            = %#x' % self.SegGs[0],
            '  ss            = %#x' % self.SegSs[0],
            '  eflags        = %#x' % self.EFlags[0],
            '  dr0           = %#x' % self.Dr0[0],
            '  dr1           = %#x' % self.Dr1[0],
            '  dr2           = %#x' % self.Dr2[0],
            '  dr3           = %#x' % self.Dr3[0],
            '  dr6           = %#x' % self.Dr6[0],
            '  dr7           = %#x' % self.Dr7[0],
            '  rax           = %#x' % self.Rax[0],
            '  rcx           = %#x' % self.Rcx[0],
            '  rdx           = %#x' % self.Rdx[0],
            '  rbx           = %#x' % self.Rbx[0],
            '  rsp           = %#x' % self.Rsp[0],
            '  rbp           = %#x' % self.Rbp[0],
            '  rsi           = %#x' % self.Rsi[0],
            '  rdi           = %#x' % self.Rdi[0],
            '  r8            = %#x' % self.R8[0],
            '  r9            = %#x' % self.R9[0],
            '  r10           = %#x' % self.R10[0],
            '  r11           = %#x' % self.R11[0],
            '  r12           = %#x' % self.R12[0],
            '  r13           = %#x' % self.R13[0],
            '  r14           = %#x' % self.R14[0],
            '  r15           = %#x' % self.R15[0],
            '  rip           = %#x' % self.Rip[0],
            ])

processorArchitecture = Enumeration({
    "PROCESSOR_ARCHITECTURE_X86"       :  0,
    "PROCESSOR_ARCHITECTURE_MIPS"      :  1,
    "PROCESSOR_ARCHITECTURE_ALPHA"     :  2,
    "PROCESSOR_ARCHITECTURE_PPC"       :  3,
    "PROCESSOR_ARCHITECTURE_SHX"       :  4,
    "PROCESSOR_ARCHITECTURE_ARM"       :  5,
    "PROCESSOR_ARCHITECTURE_IA64"      :  6,
    "PROCESSOR_ARCHITECTURE_ALPHA64"   :  7,
    "PROCESSOR_ARCHITECTURE_MSIL"      :  8,
    "PROCESSOR_ARCHITECTURE_AMD64"     :  9,
    "PROCESSOR_ARCHITECTURE_X86_WIN64" : 10,
    "PROCESSOR_ARCHITECTURE_UNKNOWN"   : 0xffff,
})

class Thread(CStruct):
    """MINIDUMP_THREAD
    https://msdn.microsoft.com/en-us/library/ms680517(v=vs.85).aspx
    """

    arch2context_cls = {
        processorArchitecture.PROCESSOR_ARCHITECTURE_X86: Context_x86,
        processorArchitecture.PROCESSOR_ARCHITECTURE_AMD64: Context_AMD64,
    }

    def parse_context(self, content, offset):
        self.loc_desc = LocationDescriptor.unpack(content, offset, self.parent_head)

        # Use the correct context depending on architecture
        systeminfo = self.parent_head.systeminfo
        context_cls = self.arch2context_cls.get(systeminfo.ProcessorArchitecture,
                                                None)
        if context_cls is None:
            raise ValueError("Unsupported architecture: %s" % systeminfo.pretty_processor_architecture)

        ctxt = context_cls.unpack(content, self.loc_desc.Rva.rva, self.parent_head)
        fake_loc_descriptor = LocationDescriptor(DataSize=0, Rva=Rva(rva=0))
        return ctxt, offset + len(fake_loc_descriptor)

    _fields = [("ThreadId", "u32"),
               ("SuspendCount", "u32"),
               ("PriorityClass", "u32"),
               ("Priority", "u32"),
               ("Teb", "u64"),
               ("Stack", "MemoryDescriptor"),
               ("ThreadContext", (parse_context,
                                  lambda thread, value: NotImplemented)),
    ]
    def dump(self):
        return '\n'.join([
            'MDRawThread',
            '  thread_id                   = %#x' % self.ThreadId,
            '  suspend_count               = %d' % self.SuspendCount,
            '  priority_class              = %#x' % self.PriorityClass,
            '  priority                    = %#x' % self.Priority,
            '  teb                         = %#x' % self.Teb,
            '  stack.start_of_memory_range = %#x' % self.Stack.StartOfMemoryRange,
            '  stack.memory.data_size      = %#x' % self.Stack.Memory.DataSize,
            '  stack.memory.rva            = %#x' % self.Stack.Memory.Rva.rva,
            '  thread_context.data_size    = %#x' % self.loc_desc.DataSize,
            '  thread_context.rva          = %#x' % self.loc_desc.Rva.rva,
            ])

class ThreadList(CStruct):
    """MINIDUMP_THREAD_LIST
    https://msdn.microsoft.com/en-us/library/ms680515(v=vs.85).aspx
    """
    _fields = [("NumberOfThreads", "u32"),
               ("Threads", "Thread",
                lambda mlist: mlist.NumberOfThreads),
    ]

class ThreadListWithPadding(CStruct):
    """MINIDUMP_THREAD_LIST may have 4 bytes padding
    https://chromium.googlesource.com/breakpad/breakpad/+/master/src/processor/minidump.cc
    cf. function MinidumpThreadList::Read
    """
    _fields = [("NumberOfThreads", "u32"),
               ("Padding", "u32"),
               ("Threads", "Thread",
                lambda mlist: mlist.NumberOfThreads),
    ]


class Exception(Thread):
    _fields = [("ThreadId", "u32"),
               ("A", "u32"),
               ("ExceptionCode", "u32"),
               ("ExceptionFlags", "u32"),
               ("ExceptionRecord", "u64"),
               ("ExceptionAddress", "u64"),
               ("NumberParameters", "u32"),
               ("Align", "u32"),
               ("ExceptionInformation", "u64", lambda _:15),
               ("ThreadContext", (Thread.parse_context,
                                  lambda thread, value: NotImplemented)),
    ]
    def dump(self):
        res = [
            'MDException',
            '  thread_id                                  = %#x' % self.ThreadId,
            '  exception_record.exception_code            = %#x' % self.ExceptionCode,
            '  exception_record.exception_flags           = %#x' % self.ExceptionFlags,
            '  exception_record.exception_record          = %#x' % self.ExceptionRecord,
            '  exception_record.exception_address         = %#x' % self.ExceptionAddress,
            '  exception_record.number_parameters         = %d' % self.NumberParameters,
            ]
        for i in range(self.NumberParameters):
            res.append('  exception_record.exception_information[%2d] = %#x' % (i, self.ExceptionInformation[i]))
        res.extend([
            '  thread_context.data_size                   = %d' % self.loc_desc.DataSize,
            '  thread_context.rva                         = %#x' % self.loc_desc.Rva.rva,
            ])
        return '\n'.join(res)

class MDSystemTime(CStruct):
    _fields = [("Year","u16"),
               ("Month","u16"),
               ("DayOfTheWeek","u16"),
               ("Day","u16"),
               ("Hour","u16"),
               ("Minute","u16"),
               ("Second","u16"),
               ("Milliseconds","u16"),
    ]
    def dump(self):
        return '%04d-%02d-%02d (%d) %02d:%02d:%02d.%03d' % (self.Year, self.Month, self.Day, self.DayOfTheWeek, self.Hour, self.Minute, self.Second, self.Milliseconds)

class MDTimeZoneInformation(CStruct):
    _fields = [("Bias","s32"),
               ("StandardName","64s"), # utf-16
               ("StandardDate","MDSystemTime"),
               ("StandardBias","s32"),
               ("DaylightTime","64s"), # utf-16
               ("DaylightDate","MDSystemTime"),
               ("DaylightBias","s32"),
    ]

class MDXStateFeature(CStruct):
    _fields = [("Offset","u32"),
               ("Size","u32"),
    ]

class MDXStateConfigFeatureMscInfo(CStruct):
    _fields = [("SizeOfInfo","u32"),
               ("ContextSize","u32"),
               ("EnabledFeatures","u64"),
               ("Features","MDXStateFeature",lambda _:64),
    ]

MD_MISCINFO_FLAGS1_PROCESS_ID            = 0x00000001
MD_MISCINFO_FLAGS1_PROCESS_TIMES         = 0x00000002
MD_MISCINFO_FLAGS1_PROCESSOR_POWER_INFO  = 0x00000004
MD_MISCINFO_FLAGS1_PROCESS_INTEGRITY     = 0x00000010
MD_MISCINFO_FLAGS1_PROCESS_EXECUTE_FLAGS = 0x00000020
MD_MISCINFO_FLAGS1_TIMEZONE              = 0x00000040
MD_MISCINFO_FLAGS1_PROTECTED_PROCESS     = 0x00000080
MD_MISCINFO_FLAGS1_BUILDSTRING           = 0x00000100
MD_MISCINFO_FLAGS1_PROCESS_COOKIE        = 0x00000200

MD_MISCINFO_SIZE  = 24
MD_MISCINFO2_SIZE = 44
MD_MISCINFO3_SIZE = 232
MD_MISCINFO4_SIZE = 832
MD_MISCINFO5_SIZE = 1364

class MiscInfo(CStruct):
    _fields = [("SizeOfInfo","u32"),
               # Version 1 fields
               ("Flags1","u32"),
               ("ProcessId","u32"),
               ("ProcessCreateTime","u32"),
               ("ProcessUserTime","u32"),
               ("ProcessKernelTime","u32"),
               # Version 2 fields
               ("ProcessorMaxMhz","u32"),
               ("ProcessorCurrentMhz","u32"),
               ("ProcessorMhzLimit","u32"),
               ("ProcessorMaxIdleState","u32"),
               ("ProcessorCurrentIdleState","u32"),
               # Version 3 fields
               ("ProcessIntegrityLevel","u32"),
               ("ProcessExecuteFlags","u32"),
               ("ProtectedProcess","u32"),
               ("TimeZoneId","u32"),
               ("TimeZone","MDTimeZoneInformation"),
               # Version 4 fields
               ("BuildString","520s"),
               ("DbgBldStr","80s"),
               # Version 5 fields
               ("XstateData","MDXStateConfigFeatureMscInfo"),
               ("ProcessCookie","u32"),
    ]
    @property
    def process_execute_flags(self):
        if self.Flags1 & MD_MISCINFO_FLAGS1_PROCESS_EXECUTE_FLAGS:
            return '%#x' % self.ProcessExecuteFlags
        else:
            return '(invalid)'
    def dump(self):
        res = [
            'MDRawMiscInfo',
            '  size_of_info                 = %d' % self.SizeOfInfo,
            '  flags1                       = %#x' % self.Flags1,
            '  process_id                   = %d' % self.ProcessId,
            '  process_create_time          = %s' % time_str(self.ProcessCreateTime),
            '  process_user_time            = %s' % time_str(self.ProcessUserTime,zero=True),
            '  process_kernel_time          = %s' % time_str(self.ProcessKernelTime,zero=True),
            ]
        if self.SizeOfInfo > MD_MISCINFO_SIZE: res += [
            # Print version 2 fields
            '  processor_max_mhz            = %d' % self.ProcessorMaxMhz,
            '  processor_current_mhz        = %d' % self.ProcessorCurrentMhz,
            '  processor_mhz_limit          = %d' % self.ProcessorMhzLimit,
            '  processor_max_idle_state     = %d' % self.ProcessorMaxIdleState,
            '  processor_current_idle_state = %d' % self.ProcessorCurrentIdleState,
            ]
        if self.SizeOfInfo > MD_MISCINFO2_SIZE: res += [
            # Print version 3 fields
            '  process_integrity_level      = %#x' % self.ProcessIntegrityLevel,
            '  process_execute_flags        = %s' % self.process_execute_flags,
            '  protected_process            = %d' % self.ProtectedProcess,
            '  time_zone_id                 = %d' % self.TimeZoneId,
            '  time_zone.bias               = %d' % self.TimeZone.Bias,
            '  time_zone.standard_name      = %s' % self.TimeZone.StandardName.decode('utf-16').strip('\0'),
            '  time_zone.standard_date      = %s' % self.TimeZone.StandardDate.dump(),
            '  time_zone.standard_bias      = %d' % self.TimeZone.StandardBias,
            '  time_zone.daylight_name      = %s' % self.TimeZone.DaylightTime.decode('utf-16').strip('\0'),
            '  time_zone.daylight_date      = %s' % self.TimeZone.DaylightDate.dump(),
            '  time_zone.daylight_bias      = %d' % self.TimeZone.DaylightBias,
            ]
        if self.SizeOfInfo > MD_MISCINFO3_SIZE: res += [
            # Print version 4 fields
            '  build_string                 = %s' % self.BuildString.decode('utf-16').strip('\0'),
            '  dbg_bld_str                  = %s' % self.DbgBldStr.decode('utf-16').strip('\0'),
            ]
        if self.SizeOfInfo > MD_MISCINFO4_SIZE: res += [
            # Print version 5 fields
            '  xstate_data.size_of_info     = %d' % self.XstateData.SizeOfInfo,
            '  xstate_data.context_size     = %d' % self.XstateData.ContextSize,
            '  xstate_data.enabled_features = %#x' % self.XstateData.EnabledFeatures,
            ]
        if self.SizeOfInfo > MD_MISCINFO4_SIZE and \
           self.XstateData.EnabledFeatures == 0:
            res.append('  xstate_data.features[]       = (empty)')
        if self.SizeOfInfo > MD_MISCINFO4_SIZE:
            res.append('  process_cookie               = %d' % self.ProcessCookie)
        return '\n'.join(res)

class BreakpadAssertion(CStruct):
    _fields = [("Expression","256s"),
               ("Function","256s"),
               ("File","256s"),
               ("Line","u32"),
               ("Type","u32"),
    ]
    def dump(self):
        return '\n'.join([
            'MDAssertion',
            '  expression                                 = %s' % self.Expression.decode('utf-16').strip('\0'),
            '  function                                   = %s' % self.Function.decode('utf-16').strip('\0'),
            '  file                                       = %s' % self.File.decode('utf-16').strip('\0'),
            '  line                                       = %d' % self.Line,
            '  type                                       = %d' % self.Type,
            ])

MD_BREAKPAD_INFO_VALID_DUMP_THREAD_ID       = 0x0001
MD_BREAKPAD_INFO_VALID_REQUESTING_THREAD_ID = 0x0002
class BreakpadRawInfo(CStruct):
    _fields = [("Validity","u32"),
               ("DumpThreadId","u32"),
               ("RequestingThreadId","u32"),
    ]
    @property
    def dump_thread_id(self):
        if self.Validity & MD_BREAKPAD_INFO_VALID_DUMP_THREAD_ID:
            return '%#x' % self.DumpThreadId
        else:
            return '(invalid)'
    @property
    def requesting_thread_id(self):
        if self.Validity & MD_BREAKPAD_INFO_VALID_REQUESTING_THREAD_ID:
            return '%#x' % self.RequestingThreadId
        else:
            return '(invalid)'
    def dump(self):
        return '\n'.join([
            'MDRawBreakpadInfo',
            '  validity             = %#x' % self.Validity,
            '  dump_thread_id       = %s' % self.dump_thread_id,
            '  requesting_thread_id = %s' % self.requesting_thread_id,
            ])

MD_OS_WIN32S        = 0 # VER_PLATFORM_WIN32s (Windows 3.1)
MD_OS_WIN32_WINDOWS = 1 # VER_PLATFORM_WIN32_WINDOWS (Windows 95-98-Me)
MD_OS_WIN32_NT      = 2 # VER_PLATFORM_WIN32_NT (Windows NT, 2000+)
MD_OS_WIN32_CE      = 3 # VER_PLATFORM_WIN32_CE, VER_PLATFORM_WIN32_HH (Windows CE, Windows Mobile, "Handheld")
# The following values are Breakpad-defined.
MD_OS_UNIX          = 0x8000 # Generic Unix-ish
MD_OS_MAC_OS_X      = 0x8101 # Mac OS X/Darwin
MD_OS_IOS           = 0x8102 # iOS
MD_OS_LINUX         = 0x8201 # Linux
MD_OS_SOLARIS       = 0x8202 # Solaris
MD_OS_ANDROID       = 0x8203 # Android
MD_OS_PS3           = 0x8204 # PS3
MD_OS_NACL          = 0x8205 # Native Client (NaCl)

MD_CPU_ARCHITECTURE_X86       =  0 # PROCESSOR_ARCHITECTURE_INTEL
MD_CPU_ARCHITECTURE_MIPS      =  1 # PROCESSOR_ARCHITECTURE_MIPS
MD_CPU_ARCHITECTURE_ALPHA     =  2 # PROCESSOR_ARCHITECTURE_ALPHA
MD_CPU_ARCHITECTURE_PPC       =  3 # PROCESSOR_ARCHITECTURE_PPC
MD_CPU_ARCHITECTURE_SHX       =  4 # PROCESSOR_ARCHITECTURE_SHX (Super-H)
MD_CPU_ARCHITECTURE_ARM       =  5 # PROCESSOR_ARCHITECTURE_ARM
MD_CPU_ARCHITECTURE_IA64      =  6 # PROCESSOR_ARCHITECTURE_IA64
MD_CPU_ARCHITECTURE_ALPHA64   =  7 # PROCESSOR_ARCHITECTURE_ALPHA64
MD_CPU_ARCHITECTURE_MSIL      =  8 # PROCESSOR_ARCHITECTURE_MSIL (Microsoft Intermediate Language)
MD_CPU_ARCHITECTURE_AMD64     =  9 # PROCESSOR_ARCHITECTURE_AMD64
MD_CPU_ARCHITECTURE_X86_WIN64 = 10 # PROCESSOR_ARCHITECTURE_IA32_ON_WIN64 (WoW64)
MD_CPU_ARCHITECTURE_SPARC     = 0x8001 # Breakpad-defined value for SPARC
MD_CPU_ARCHITECTURE_PPC64     = 0x8002 # Breakpad-defined value for PPC64
MD_CPU_ARCHITECTURE_ARM64     = 0x8003 # Breakpad-defined value for ARM64
MD_CPU_ARCHITECTURE_MIPS64    = 0x8004 # Breakpad-defined value for MIPS64
MD_CPU_ARCHITECTURE_UNKNOWN   = 0xffff # PROCESSOR_ARCHITECTURE_UNKNOWN


class SystemInfo(CStruct):
    """MINIDUMP_SYSTEM_INFO
    https://msdn.microsoft.com/en-us/library/ms680396(v=vs.85).aspx
    """
    _fields = [("ProcessorArchitecture", "u16"),
               ("ProcessorLevel", "u16"),
               ("ProcessorRevision", "u16"),
               ("NumberOfProcessors", "u08"),
               ("ProductType", "u08"),
               ("MajorVersion", "u32"),
               ("MinorVersion", "u32"),
               ("BuildNumber", "u32"),
               ("PlatformId", "u32"),
               ("CSDVersionRva", "Rva"),
               ("SuiteMask", "u16"),
               ("Reserved2", "u16"),
               ("ProcessorFeatures", "u64", lambda _: 3),
    ]
    # The following fields are x86-only
    VendorId = property(lambda _:[
        _.ProcessorFeatures[0]&0xffffffff,
        _.ProcessorFeatures[0]>>32,
        _.ProcessorFeatures[1]&0xffffffff])
    VersionInformation = property(lambda _:_.ProcessorFeatures[1]>>32)
    FeatureInformation = property(lambda _:_.ProcessorFeatures[2]&0xffffffff)
    AMDExtendedCpuFeatures = property(lambda _:_.ProcessorFeatures[2]>>32)
    # The following fields are arm-only
    Cpuid = property(lambda _:_.ProcessorFeatures[0]&0xffffffff)
    ElfHwcaps = property(lambda _:_.ProcessorFeatures[0]>>32) # Linux-specific

    @property
    def pretty_processor_architecture(self):
        return processorArchitecture[self.ProcessorArchitecture]

    @property
    def csd_version(self):
        return MinidumpString.unpack(self.parent_head._content,
                                     off = self.CSDVersionRva.rva,
                                     parent_head = self.parent_head)

    @property
    def cpu_vendor(self):
        if self.ProcessorArchitecture in (MD_CPU_ARCHITECTURE_X86,
                                          MD_CPU_ARCHITECTURE_X86_WIN64):
            import struct
            return '"'+struct.pack("<III", *self.VendorId).decode('latin1')+'"'
        return '(null)'

    def dump(self):
        res = [
            'MDRawSystemInfo',
            '  processor_architecture                     = %#x' % self.ProcessorArchitecture,
            '  processor_level                            = %d' % self.ProcessorLevel,
            '  processor_revision                         = %#x' % self.ProcessorRevision,
            '  number_of_processors                       = %d' % self.NumberOfProcessors,
            '  product_type                               = %d' % self.ProductType,
            '  major_version                              = %d' % self.MajorVersion,
            '  minor_version                              = %d' % self.MinorVersion,
            '  build_number                               = %d' % self.BuildNumber,
            '  platform_id                                = %#x' % self.PlatformId,
            '  csd_version_rva                            = %#x' % self.CSDVersionRva.rva,
            '  suite_mask                                 = %#x' % self.SuiteMask,
            ]
        if self.ProcessorArchitecture in (MD_CPU_ARCHITECTURE_X86,
                                          MD_CPU_ARCHITECTURE_X86_WIN64):
            res.append('  cpu.x86_cpu_info (valid):')
        else:
            res.append('  cpu.x86_cpu_info (invalid):')
        res.extend([
            '  cpu.x86_cpu_info.vendor_id[0]              = %#x' % self.VendorId[0],
            '  cpu.x86_cpu_info.vendor_id[1]              = %#x' % self.VendorId[1],
            '  cpu.x86_cpu_info.vendor_id[2]              = %#x' % self.VendorId[2],
            '  cpu.x86_cpu_info.version_information       = %#x' % self.VersionInformation,
            '  cpu.x86_cpu_info.feature_information       = %#x' % self.FeatureInformation,
            '  cpu.x86_cpu_info.amd_extended_cpu_features = %#x' % self.AMDExtendedCpuFeatures,
            ])
        if not self.ProcessorArchitecture in (MD_CPU_ARCHITECTURE_X86,
                                              MD_CPU_ARCHITECTURE_X86_WIN64):
            res.extend([
            '  cpu.other_cpu_info (valid):',
            '  cpu.other_cpu_info.processor_features[0]   = %#x' % self.ProcessorFeatures[0],
            '  cpu.other_cpu_info.processor_features[1]   = %#x' % self.ProcessorFeatures[1],
            ])
        res.extend([
            '  (csd_version)                              = "%s"' % self.csd_version,
            '  (cpu_vendor)                               = %s' % self.cpu_vendor,
            ])
        return '\n'.join(res)
