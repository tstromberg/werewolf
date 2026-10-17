"""Exercise an FFI callback while executable-memory gain remains prohibited."""
import ctypes
from pathlib import Path

libc = ctypes.CDLL(None)
libc.prctl.argtypes = [ctypes.c_int] + [ctypes.c_ulong] * 4
libc.prctl.restype = ctypes.c_int
flags = libc.prctl(66, 0, 0, 0, 0)
assert flags >= 0 and flags & 1, "PR_MDWE_REFUSE_EXEC_GAIN is required"
callback = ctypes.CFUNCTYPE(ctypes.c_int, ctypes.c_int)(lambda value: value + 1)
assert callback(41) == 42
for line in Path("/proc/self/maps").read_text().splitlines():
    flags = line.split()[1]
    assert not ("w" in flags and "x" in flags), line
print("ffi-callback: ok")
