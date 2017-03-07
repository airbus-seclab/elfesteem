#! /usr/bin/env python

from distutils.core import setup

setup(
    name = 'ELFEsteem',
    version = '0.2',
    packages=['elfesteem'],
    scripts = ['elfcli'],
    # Metadata
    author = 'Philippe BIONDI',
    author_email = 'phil(at)secdev.org',
    description = 'ELFEsteem: ELF/PE/Mach-O file manipulation library',
    license = 'LGPLv2.1',
    # keywords = '',
    # url = '',
)
