#! /usr/bin/env python

from distutils.core import setup

setup(
    name = 'ELF-Esteem',
    version = '0.1',    
    packages = ['elfesteem'],
    requires = ['python (>= 2.4)'],
    scripts = ['examples/readelf.py','examples/otool.py','examples/readpe.py'],
    # Metadata
    author = 'Philippe BIONDI',
    author_email = 'phil(at)secdev.org',
    description = 'ELF-Esteem: ELF file manipulation library',
    license = 'LGPLv2.1',
    url = 'https://github.com/airbus-seclab/elfesteem',
    # keywords = '',
)
