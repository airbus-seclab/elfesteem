#! /usr/bin/env python

from cstruct import CStruct

class Doshdr(CStruct):
    _fields = [ ("magic", "u16"),
                ("cblp","u16"),
                ("cp","u16"),
                ("crlc","u16"),
                ("cparhdr","u16"),
                ("minalloc","u16"),
                ("maxalloc","u16"),
                ("ss","u16"),
                ("sp","u16"),
                ("csum","u16"),
                ("ip","u16"),
                ("cs","u16"),
                ("lfarlc","u16"),
                ("ovno","u16"),
                ("res","8s"),
                ("oemid","u16"),
                ("oeminfo","u16"),
                ("res2","20s"),
                ("lfanew","u32") ]

class NTsig(CStruct):
    _fields = [ ("signature","u32"),
                ]

class Coffhdr(CStruct):
    _fields = [ ("machine","u16"),
                ("numberofsections","u16"),
                ("timedatestamp","u32"),
                ("pointertosymboltable","u32"),
                ("numberofsymbols","u32"),
                ("sizeofoptionalheader","u16"),
                ("characteristics","u16") ]

class Opthdr(CStruct):
    _fields = [ ("magic","u16"),
                ("majorlinkerversion","u08"),
                ("minorlinkerversion","u08"),
                ("SizeOfCode","u32"),
                ("sizeofinitializeddata","u32"),
                ("sizeofuninitializeddata","u32"),
                ("AddressOfEntryPoint","u32"),
                ("BaseOfCode","u32"),
                ("BaseOfData","u32"),
                ("ImageBase","u32"),
                ("sectionalignment","u32"),
                ("filealignment","u32"),
                ("majoroperatingsystemversion","u16"),
                ("minoroperatingsystemversion","u16"),
                ("MajorImageVersion","u16"),
                ("MinorImageVersion","u16"),
                ("majorsubsystemversion","u16"),
                ("minorsubsystemversion","u16"),
                ("Reserved1","u32"),
                ("sizeofimage","u32"),
                ("sizeofheaders","u32"),
                ("CheckSum","u32"),
                ("subsystem","u16"),
                ("dllcharacteristics","u16"),
                ("sizeofstackreserve","u32"),
                ("sizeofstackcommit","u32"),
                ("sizeofheapreserve","u32"),
                ("sizeofheapcommit","u32"),
                ("loaderflags","u32"),
                ("numberofrvaandsizes","u32") ]

class Optehdr(CStruct):
    _fields = [ ("rva","u32"),
                ("size","u32") ]

class Shdr(CStruct):
    _fields = [ ("name","8s"),
                ("size","u32"),
                ("addr","u32"),
                ("rawsize","u32"),
                ("offset","u32"),
                ("pointertorelocations","u32"),
                ("pointertolinenumbers","u32"),
                ("numberofrelocations","u16"),
                ("numberoflinenumbers","u16"),
                ("flags","u32") ]


class Rva(CStruct):
    _fields = [ ("rva","u32"),
                ]


class ImpDesc(CStruct):
    _fields = [ ("originalfirstthunk","u32"),
                ("timestamp","u32"),
                ("forwarderchain","u32"),
                ("name","u32"),
                ("firstthunk","u32")
              ]

class ExpDesc(CStruct):
    _fields = [ ("characteristics","u32"),
                ("timestamp","u32"),
                ("majorv","u16"),
                ("minorv","u16"),
                ("name","u32"),
                ("base","u32"),
                ("numberoffunctions","u32"),
                ("numberofnames","u32"),
                ("addressoffunctions","u32"),
                ("addressofnames","u32"),
                ("addressofordinals","u32"),
              ]

class DelayDesc(CStruct):
    _fields = [ ("attrs","u32"),
                ("name","u32"),
                ("hmod","u32"),
                ("firstthunk","u32"),
                ("originalfirstthunk","u32"),
                ("boundiat","u32"),
                ("unloadiat","u32"),
                ("timestamp","u32"),
              ]

class Ordinal(CStruct):
    _fields = [ ("ordinal","u16"),
                ]

class Rel(CStruct):
    _fields = [ ("rva","u32"),
                ("size","u32")
                ]


class ResDesc(CStruct):
    _fields = [ ("characteristics","u32"),
                ("timestamp","u32"),
                ("majorv","u16"),
                ("minorv","u16"),
                ("numberofnamedentries","u16"),
                ("numberofidentries","u16")
              ]

class ResEntry(CStruct):
    _fields = [ ("name","u32"),
                ("offset2data","u32")
                ]

class ResDataEntry(CStruct):
    _fields = [ ("offsettodata","u32"),
                ("size","u32"),
                ("codepage","u32"),
                ("reserved","u32"),                
                ]


class Symb(CStruct):
    _fields = [ ("name","8s"),
                ("res1","u32"),
                ("res2","u32"),
                ("res3","u16")]


DIRECTORY_ENTRY_EXPORT           = 0
DIRECTORY_ENTRY_IMPORT           = 1
DIRECTORY_ENTRY_RESOURCE         = 2
DIRECTORY_ENTRY_EXCEPTION        = 3
DIRECTORY_ENTRY_SECURITY         = 4
DIRECTORY_ENTRY_BASERELOC        = 5
DIRECTORY_ENTRY_DEBUG            = 6
DIRECTORY_ENTRY_COPYRIGHT        = 7
DIRECTORY_ENTRY_GLOBALPTR        = 8
DIRECTORY_ENTRY_TLS              = 9
DIRECTORY_ENTRY_LOAD_CONFIG      = 10
DIRECTORY_ENTRY_BOUND_IMPORT     = 11
DIRECTORY_ENTRY_IAT              = 12
DIRECTORY_ENTRY_DELAY_IMPORT     = 13
DIRECTORY_ENTRY_COM_DESCRIPTOR   = 14
DIRECTORY_ENTRY_RESERVED         = 15


RT_CURSOR                        = 1
RT_BITMAP                        = 2
RT_ICON                          = 3
RT_MENU                          = 4
RT_DIALOG                        = 5
RT_STRING                        = 6
RT_FONTDIR                       = 7
RT_FONT                          = 8
RT_ACCELERATOR                   = 9
RT_RCDATA                        = 10
RT_MESSAGETABLE                  = 11
RT_GROUP_CURSOR                  = 12
RT_GROUP_ICON                    = 14
RT_VERSION                       = 16
RT_DLGINCLUDE                    = 17
RT_PLUGPLAY                      = 19
RT_VXD                           = 20
RT_ANICURSOR                     = 21
RT_ANIICON                       = 22
RT_HTML                          = 23
RT_MANIFEST                      = 24


RT = {
    RT_CURSOR       :"RT_CURSOR",
    RT_BITMAP       :"RT_BITMAP",
    RT_ICON         :"RT_ICON",
    RT_MENU         :"RT_MENU",
    RT_DIALOG       :"RT_DIALOG",
    RT_STRING       :"RT_STRING",
    RT_FONTDIR      :"RT_FONTDIR",
    RT_FONT         :"RT_FONT",
    RT_ACCELERATOR  :"RT_ACCELERATOR",
    RT_RCDATA       :"RT_RCDATA",
    RT_MESSAGETABLE :"RT_MESSAGETABLE",
    RT_GROUP_CURSOR :"RT_GROUP_CURSOR",
    RT_GROUP_ICON   :"RT_GROUP_ICON",
    RT_VERSION      :"RT_VERSION",
    RT_DLGINCLUDE   :"RT_DLGINCLUDE",
    RT_PLUGPLAY     :"RT_PLUGPLAY",
    RT_VXD          :"RT_VXD",
    RT_ANICURSOR    :"RT_ANICURSOR",
    RT_ANIICON      :"RT_ANIICON",
    RT_HTML         :"RT_HTML",
    RT_MANIFEST     :"RT_MANIFEST",
    }



if __name__ == "__main__":
    import sys
    PEFILE = sys.stdin
    if len(sys.argv) > 1:
        PEFILE = open(sys.argv[1])
    dhdr = Doshdr._from_file(PEFILE)
    print repr(dhdr)
    print "sigMZ:", hex(dhdr.magic),hex(len(dhdr))

    PEFILE.seek(dhdr.lfanew)
    nthdr = NThdr._from_file(PEFILE)
    print repr(nthdr)
    print "sigPE:", hex(nthdr.signature),hex(len(nthdr))

    PEFILE.seek(dhdr.lfanew+len(nthdr))
    opthdr = Opthdr._from_file(PEFILE)
    print repr(opthdr)
    print "sigHDR:",hex(opthdr.magic),hex(len(opthdr))

    PEFILE.seek(dhdr.lfanew+len(nthdr)+len(opthdr))
    for i in xrange(opthdr.numberofrvaandsizes):
        optehdr = Optehdr._from_file(PEFILE)
        print repr(optehdr)
        


    print hex(dhdr.lfanew+len(nthdr)+nthdr.sizeofoptionalheader)
    PEFILE.seek(dhdr.lfanew+len(nthdr)+nthdr.sizeofoptionalheader)
    for i in xrange(nthdr.numberofsections):
        #PEFILE.seek(dhdr.lfanew+len(nthdr))
        shdr = Shdr._from_file(PEFILE)
        print repr(shdr)
        print "name:",shdr.name,hex(len(shdr))
