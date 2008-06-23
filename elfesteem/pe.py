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
                ("misc","I"),
                ("virtualaddress","I"),
                ("sizeofrawdata","I"),
                ("pointertorawdata","I"),
                ("pointertorelocations","I"),
                ("pointertolinenumbers","I"),
                ("numberofrelocations","H"),
                ("numberoflinenumbers","H"),
                ("characteristics","I") ]




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
        


    print "_"*80
    print hex(dhdr.lfanew+len(nthdr)+nthdr.sizeofoptionalheader)
    PEFILE.seek(dhdr.lfanew+len(nthdr)+nthdr.sizeofoptionalheader)
    for i in xrange(nthdr.numberofsections):
        #PEFILE.seek(dhdr.lfanew+len(nthdr))
        shdr = Shdr._from_file(PEFILE)
        print repr(shdr)
        print "sig:",shdr.name,hex(len(shdr))
