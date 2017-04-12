#! /usr/bin/env python
"""
High-level abstraction of Minidump file
"""
import sys, os
sys.path.insert(1, os.path.abspath(sys.path[0]+'/..'))

from elfesteem.strpatchwork import StrPatchwork
from elfesteem import minidump as mp


class MemorySegment(object):
    """Stand for a segment in memory with additionnal information"""

    def __init__(self, offset, memory_desc, module=None, memory_info=None):
        self.offset = offset
        self.memory_desc = memory_desc
        self.module = module
        self.memory_info = memory_info
        self.minidump = self.memory_desc.parent_head

    @property
    def address(self):
        return self.memory_desc.StartOfMemoryRange

    @property
    def size(self):
        if isinstance(self.memory_desc, mp.MemoryDescriptor64):
            return self.memory_desc.DataSize
        elif isinstance(self.memory_desc, mp.MemoryDescriptor):
            return self.memory_desc.Memory.DataSize
        raise TypeError

    @property
    def name(self):
        if self.module:
            return self.module.ModuleName
        return ""

    @property
    def content(self):
        return self.minidump._content[self.offset:self.offset + self.size]

    @property
    def protect(self):
        if self.memory_info:
            return self.memory_info.Protect
        return None

    @property
    def pretty_protect(self):
        if self.protect is None:
            return "UNKNOWN"
        return mp.memProtect[self.protect]

    def dump(self):
        import struct
        return '0x' + ''.join(["%02x"%_ for _ in struct.unpack("%dB"%len(self.content), self.content)])


class Minidump(object):
    """Stand for a Minidump file

    Here is a few limitation:
     - only < 4GB Minidump are supported (LocationDescriptor handling)
     - only Stream relative to memory mapping are implemented

    Official description is available on MSDN:
    https://msdn.microsoft.com/en-us/library/ms680378(VS.85).aspx
    """

    _sex = 0
    _wsize = 32

    def entrypoint(self):
        if not len(self.threads.Threads): return -1
        pc_reg = ()
        if self.systeminfo.ProcessorArchitecture == \
                mp.processorArchitecture.PROCESSOR_ARCHITECTURE_X86:
            pc_reg = self.threads.Threads[0].ThreadContext.Eip
        if self.systeminfo.ProcessorArchitecture == \
                mp.processorArchitecture.PROCESSOR_ARCHITECTURE_AMD64:
            pc_reg = self.threads.Threads[0].ThreadContext.Rip
        if not len(pc_reg): return -1
        return pc_reg[0]
    architecture = property(lambda _:_.systeminfo.pretty_processor_architecture[23:])
    entrypoint = property(entrypoint)
    sections = property(lambda _:_.memory.values())
    symbols = ()
    dynsyms = ()

    def __init__(self, minidump_str):
        self._content = StrPatchwork(minidump_str)

        # Specific streams
        self.modulelist = None
        self.memory64list = None
        self.memorylist = None
        self.memoryinfolist = None
        self.systeminfo = None

        # Get information
        self.streams = []
        self.threads = None
        self.parse_content()

        # Memory information
        self.memory = {} # base address (virtual) -> Memory information
        self.build_memory()
        self.virt = ContentVirtual(self)

    def parse_content(self):
        """Build structures corresponding to current content"""

        # Header
        offset = 0
        self.minidumpHDR = mp.MinidumpHDR.unpack(self._content, offset, self)
        assert self.minidumpHDR.Magic == 0x504d444d

        # Streams
        base_offset = self.minidumpHDR.StreamDirectoryRva.rva
        empty_stream = mp.StreamDirectory(StreamType=0,
                                          Location=mp.LocationDescriptor(DataSize=0,
                                                                         Rva=mp.Rva(rva=0)
                                          )
        )
        streamdir_size = len(empty_stream)
        for i in range(self.minidumpHDR.NumberOfStreams):
            stream_offset = base_offset + i * streamdir_size
            stream = mp.StreamDirectory.unpack(self._content, stream_offset, self)
            self.streams.append(stream)

            # Launch specific action depending on the stream
            datasize = stream.Location.DataSize
            offset = stream.Location.Rva.rva
            if stream.StreamType == mp.streamType.ModuleListStream:
                self.modulelist = mp.ModuleList.unpack(self._content, offset, self)
            elif stream.StreamType == mp.streamType.MemoryListStream:
                self.memorylist = mp.MemoryList.unpack(self._content, offset, self)
            elif stream.StreamType == mp.streamType.Memory64ListStream:
                self.memory64list = mp.Memory64List.unpack(self._content, offset, self)
            elif stream.StreamType == mp.streamType.MemoryInfoListStream:
                self.memoryinfolist = mp.MemoryInfoList.unpack(self._content, offset, self)
            elif stream.StreamType == mp.streamType.SystemInfoStream:
                self.systeminfo = mp.SystemInfo.unpack(self._content, offset, self)
            elif stream.StreamType == mp.streamType.MiscInfoStream:
                self.miscinfo = mp.MiscInfo.unpack(self._content, offset, self)
            # Breakpad extension types
            elif stream.StreamType == mp.MDminidumpType.MD_ASSERTION_INFO_STREAM:
                self.breakpad_assertion = mp.BreakpadAssertion.unpack(self._content, offset, self)
            elif stream.StreamType == mp.MDminidumpType.MD_BREAKPAD_INFO_STREAM:
                self.breakpad_info = mp.BreakpadRawInfo.unpack(self._content, offset, self)

        # Some streams need the SystemInfo stream to work
        if self.systeminfo is None:
            return
        for stream in self.streams:
            datasize = stream.Location.DataSize
            offset = stream.Location.Rva.rva
            if stream.StreamType == mp.streamType.ThreadListStream:
                self.threads = mp.ThreadList.unpack(self._content, offset, self)
            elif stream.StreamType == mp.streamType.ExceptionStream:
                self.exception = mp.Exception.unpack(self._content, offset, self)


    def build_memory(self):
        """Build an easier to use memory view based on ModuleList and
        Memory64List streams"""

        addr2module = {}
        if self.modulelist:
            for module in self.modulelist.Modules:
                addr2module[module.BaseOfImage] = module
        addr2meminfo = {}
        if self.memoryinfolist:
            for memory in self.memoryinfolist.MemoryInfos:
                addr2meminfo[memory.BaseAddress] = memory

        mode64 = self.minidumpHDR.Flags & mp.minidumpType.MiniDumpWithFullMemory

        if mode64:
            offset = self.memory64list.BaseRva
            memranges = self.memory64list.MemoryRanges
        else:
            memranges = self.memorylist.MemoryRanges

        for memory in memranges:
            if not mode64:
                offset = memory.Memory.Rva.rva

            # Create a MemorySegment with augmented information
            base_address = memory.StartOfMemoryRange
            module = addr2module.get(base_address, None)
            meminfo = addr2meminfo.get(base_address, None)
            self.memory[base_address] = MemorySegment(offset, memory,
                                                      module, meminfo)

            if mode64:
                offset += memory.DataSize

        # Sanity check
        if mode64:
            assert all(addr in self.memory for addr in addr2module)

    def get(self, virt_start, virt_stop):
        """Return the content at the (virtual addresses)
        [virt_start:virt_stop]"""

        # Find the corresponding memory segment
        for addr in self.memory:
            if virt_start <= addr <= virt_stop:
                break
        else:
            return ""

        memory = self.memory[addr]
        shift = addr - virt_start
        last = virt_stop - addr
        if last > memory.size:
            raise RuntimeError("Multi-page not implemented")

        return self._content[memory.offset + shift:memory.offset + last]

    def dump(self):
        """
        Same output as minidump_dump from
        https://chromium.googlesource.com/breakpad/breakpad
        """
        res = [ self.minidumpHDR.dump() ]
        streams_by_type = {} # Duplicates will not be shown
        for i, s in enumerate(self.streams):
            streams_by_type[s.StreamType] = (i, s)
            res.extend(["", "mDirectory[%d]"%i, s.dump()])
        res.append("\nStreams:")
        for t in sorted(streams_by_type.keys()):
            i, s = streams_by_type[t]
            res.append("  stream type %s at index %d" % (s.type_with_name, i))
        res.extend(["",
            "MinidumpThreadList",
            "  thread_count = %d" % self.threads.NumberOfThreads])
        for i, t in enumerate(self.threads.Threads):
            res.extend(["",
                "thread[%d]"%i,
                t.dump(),
                "",
                t.ThreadContext.dump(),
                "",
                "Stack",
                self.memory[t.Stack.StartOfMemoryRange].dump(),
                ])
        res.extend(["",
            "MinidumpModuleList",
            "  module_count = %d" % self.modulelist.NumberOfModules])
        for i, m in enumerate(self.modulelist.Modules):
            res.extend(["",
                "module[%d]"%i,
                m.dump(),
                m.dump_other(),
                ])
        res.extend(["",
            "MinidumpMemoryList",
            "  region_count = %d" % self.memorylist.NumberOfMemoryRanges])
        for i, m in enumerate(self.memorylist.MemoryRanges):
            res.extend(["",
                "region[%d]"%i,
                m.dump(),
                "Memory",
                self.memory[m.StartOfMemoryRange].dump(),
                ])
        if hasattr(self, 'exception'):
            res.extend(["",
                self.exception.dump(),
                "",
                self.exception.ThreadContext.dump(),
                ])
        if hasattr(self, 'breakpad_assertion'):
            res.extend(["",self.breakpad_assertion.dump(),""])
        res.extend([self.systeminfo.dump(),""])
        if hasattr(self, 'miscinfo'):
            res.extend([self.miscinfo.dump(),""])
        if hasattr(self, 'breakpad_info'):
            res.extend([self.breakpad_info.dump(),""])
        return '\n'.join(res)

class ContentVirtual(object):
    """ Stub for binary.py """
    def __init__(self, minidump):
        self.parent = minidump
    def max_addr(self):
        ad = -1
        for memory in self.parent.memory.values():
            ad = max(ad, memory.address+memory.size)
        return ad

if __name__ == "__main__":
    for file in sys.argv[1:]:
        if len(sys.argv) > 2: print("File: %s"%file)
        raw = open(file, 'rb').read()
        e = Minidump(raw)
        print(e.dump())
