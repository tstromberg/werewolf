"""Resolve Twisted's libc dependency without a linker or compiler process."""

import ctypes.util

_find_library = ctypes.util.find_library


def find_library(name):
    if name == "c":
        # The upstream image uses glibc on both supported architectures.
        return "libc.so.6"
    return _find_library(name)


ctypes.util.find_library = find_library
