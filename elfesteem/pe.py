#! /usr/bin/env python

from cstruct import CStruct

class Doshdr(CStruct):
    _fields = [ ("magic", "H"),
                ("cblp","H"),
                ("cp","H"),
                ("crlc","H"),
                ("cparhdr","H"),
                ("minalloc","H"),
                ("maxalloc","H"),
                ("ss","H"),
                ("sp","H"),
                ("csum","H"),
                ("ip","H"),
                ("cs","H"),
                ("lfarlc","H"),
                ("ovno","H"),
                ("res","8s"),
                ("oemid","H"),
                ("oeminfo","H"),
                ("res2","20s"),
                ("lfanew","I") ]

class NThdr(CStruct):
    _fields = [ ("signature","I"),
                ("machine","H"),
                ("numberofsections","H"),
                ("timedatestamp","I"),
                ("pointertosymboltable","I"),
                ("numberofsymbols","I"),
                ("sizeofoptionalheader","H"),
                ("characteristics","H") ]

class Coffhdr(CStruct):
    _fields = [ ("machine","H"),
                ("numberofsections","H"),
                ("timedatestamp","I"),
                ("pointertosymboltable","I"),
                ("numberofsymbols","I"),
                ("sizeofoptionalheader","H"),
                ("characteristics","H") ]

class Opthdr(CStruct):
    _fields = [ ("magic","H"),
                ("majorlinkerversion","B"),
                ("minorlinkerversion","B"),
                ("SizeOfCode","I"),
                ("sizeofinitializeddata","I"),
                ("sizeofuninitializeddata","I"),
                ("AddressOfEntryPoint","I"),
                ("BaseOfCode","I"),
                ("BaseOfData","I"),
                ("ImageBase","I"),
                ("sectionalignment","I"),
                ("filealignment","I"),
                ("majoroperatingsystemversion","H"),
                ("minoroperatingsystemversion","H"),
                ("MajorImageVersion","H"),
                ("MinorImageVersion","H"),
                ("majorsubsystemversion","H"),
                ("minorsubsystemversion","H"),
                ("Reserved1","I"),
                ("sizeofimage","I"),
                ("sizeofheaders","I"),
                ("CheckSum","I"),
                ("subsystem","H"),
                ("dllcharacteristics","H"),
                ("sizeofstackreserve","I"),
                ("sizeofstackcommit","I"),
                ("sizeofheapreserve","I"),
                ("sizeofheapcommit","I"),
                ("loaderflags","I"),
                ("numberofrvaandsizes","I") ]

class Optehdr(CStruct):
    _fields = [ ("rva","I"),
                ("size","I") ]

class Shdr(CStruct):
    _fields = [ ("name","8s"),
                ("size","I"),
                ("addr","I"),
                ("rawsize","I"),
                ("offset","I"),
                ("pointertorelocations","I"),
                ("pointertolinenumbers","I"),
                ("numberofrelocations","H"),
                ("numberoflinenumbers","H"),
                ("flags","I") ]


class Rva(CStruct):
    _fields = [ ("rva","I"),
                ]


class ImpDesc(CStruct):
    _fields = [ ("originalfirstthunk","I"),
                ("timestamp","I"),
                ("forwarderchain","I"),
                ("name","I"),
                ("firstthunk","I")
              ]

class ExpDesc(CStruct):
    _fields = [ ("characteristics","I"),
                ("timestamp","I"),
                ("majorv","H"),
                ("minorv","H"),
                ("name","I"),
                ("base","I"),
                ("numberoffunctions","I"),
                ("numberofnames","I"),
                ("addressoffunctions","I"),
                ("addressofnames","I"),
                ("addressofordinals","I"),
              ]


class Ordinal(CStruct):
    _fields = [ ("ordinal","H"),
                ]

class Rel(CStruct):
    _fields = [ ("rva","I"),
                ("size","I")
                ]


class ResDesc(CStruct):
    _fields = [ ("characteristics","I"),
                ("timestamp","I"),
                ("majorv","H"),
                ("minorv","H"),
                ("numberofnamedentries","H"),
                ("numberofidentries","H")
              ]

class ResEntry(CStruct):
    _fields = [ ("name","I"),
                ("offset2data","I")
                ]

class ResDataEntry(CStruct):
    _fields = [ ("offsettodata","I"),
                ("size","I"),
                ("codepage","I"),
                ("reserved","I"),                
                ]



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
