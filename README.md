# Why this fork? #

* Adding Mach-O support
* Following python recommendations: str() should return printable strings, therefore pack() is to be used
* Useable with Python ≥ 2.5 and Python 3 (ELF and Mach-O only: PE needs lots of recoding)
* ELF: many corrections, elf64 support, elf relocatable support in virt (many sections begin at address 0)
* tools: partial re-implementation of readelf and otool
* intervals: automatic detection if the whole file has not been parsed (Mach-O only)
* PE: parse the symbol table