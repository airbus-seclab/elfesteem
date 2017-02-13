# Why this fork? #

* Adding Mach-O support
* Following python recommendations: str() should return printable strings, therefore pack() is to be used
* Useable with Python ≥ 2.5 and Python 3 (some functions still need Python 2.7)
* ELF: many corrections, elf64 support, elf relocatable support in virt (many sections begin at address 0)
* tools: partial re-implementation of readelf and otool
* intervals: automatic detection if the whole file has not been parsed (Mach-O only)
* PE: parse the symbol table
* ELF: can generate a valid ELF relocatable with default values
* PE & COFF: use the same CStruct implementation as ELF, which IMHO makes it more understandable; the original API for manipulating PE files should still be useable; please tell me what worked and has been broken!