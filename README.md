# ELF Esteem #

## Overview

The goal of this library is to manipulate various containers of executable code.
ELF, PE, COFF and Mach-O files are fully supported.
It includes a partial support of Minidump and RPRC files, and a non-working implementation of Java classes.

It aims at being self-contained and portable: it is pure python, compatible from python 2.3 upwards.

## Parsing with ELF Esteem

[binary.py](elfesteem/binary.py)
can be used to read a binary of any known format and display its main characteristics.

[readelf.py](examples/readelf.py)
outputs the same as binutils' readelf, using ELF Esteem.

[otool.py](examples/otool.py)
outputs the same as MacOSX otool and dyldinfo, using ELF Esteem.

[readpe.py](examples/readpe.py)
analyses the content of a PE or COFF file, including a hierarchical display of the layout of the file.

## File manipulation with ELF Esteem

Most of the internal representation of the file parsed by ELF Esteem is based on [cstruct.py](elfesteem/cstruct.py) which is a generic framework to manipulate binary data structures.

The file is fully loaded using one of the classes `ELF`, `PE`, `COFF`, `MACHO`, `RPRC`, or `Minidump`. This class is the root of a tree of subclasses (e.g. file header, list of sections, ...) and each subtree can be modified. The method `pack()` reconstructs a binary.

The philosophy behind ELF Esteem is that if the input file is valid, and no modification is made to the internal representation, then `pack()` will recover the input.
When modifications are made, then (depending on the details of the file format) some values are automatically recomputed (e.g. fields containing lengths, checksums).

**More doc soon.**

## Development status

[![codecov](https://codecov.io/gh/LRGH/elfesteem/branch/master/graph/badge.svg)](https://codecov.io/gh/LRGH/elfesteem)
[![Build Status](https://github.com/LRGH/elfesteem/workflows/Python%20package/badge.svg?event=push)](https://github.com/LRGH/elfesteem/actions?query=workflow%3A%22Python+package%22+branch%3Amaster+event%3Apush) <!-- ignore_ppi -->
[![Build Status](https://travis-ci.org/LRGH/elfesteem.svg?branch=master)](https://travis-ci.org/LRGH/elfesteem)
