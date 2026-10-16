"""Build inotify_simple's three libc calls without runtime FFI or executable memory."""
from pathlib import Path
import errno
import os
import py_compile
import sys
import tempfile

from cffi import FFI


site = Path(sys.argv[1])
ffi = FFI()
ffi.cdef("""
    int inotify_init1(int flags);
    int inotify_add_watch(int fd, const char *path, unsigned int mask);
    int inotify_rm_watch(int fd, int wd);
""")
ffi.set_source("_werewolf_inotify", "#include <sys/inotify.h>")
ffi.compile(tmpdir="/tmp/werewolf-inotify", target=str(site / "_werewolf_inotify.*"))

# Keep upstream's event decoding, polling, EINTR handling and public interface.
# CFFI's compiled API calls libc directly; no foreign callbacks are needed.
path = site / "inotify_simple.py"
source = path.read_text()
for old, new in (
    ("from ctypes import CDLL, get_errno, c_int",
     "from _werewolf_inotify import ffi, lib as _libc"),
    ("from ctypes.util import find_library\n", ""),
    ("_libc = None\n", ""),
    ("errno = get_errno()", "errno = ffi.errno"),
    ("        global _libc; _libc = _libc or CDLL(find_library('c'), use_errno=True)\n", ""),
    ("bytes_avail = c_int()", 'bytes_avail = ffi.new("int *")'),
    ("ioctl(self, FIONREAD, bytes_avail)", "ioctl(self, FIONREAD, ffi.buffer(bytes_avail))"),
    ("if not bytes_avail.value:", "if not bytes_avail[0]:"),
    ("os.read(self.fileno(), bytes_avail.value)", "os.read(self.fileno(), bytes_avail[0])"),
):
    if source.count(old) != 1:
        raise SystemExit(f"inotify_simple changed: expected exactly one {old!r}")
    source = source.replace(old, new)
path.write_text(source)
py_compile.compile(str(path), doraise=True)

# Exercise actual kernel events, descriptor flags and error propagation before
# packaging the adapter. The form's VM tests cover the queue under confinement.
from inotify_simple import INotify, flags

with tempfile.TemporaryDirectory() as directory:
    with INotify(nonblocking=True) as watcher:
        assert not os.get_inheritable(watcher.fileno())
        wd = watcher.add_watch(directory, flags.CREATE)
        Path(directory, "event").touch()
        events = watcher.read(timeout=1000)
        assert any(e.wd == wd and e.name == "event" and e.mask & flags.CREATE for e in events)
        watcher.rm_watch(wd)
        try:
            watcher.add_watch(os.path.join(directory, "missing"), flags.CREATE)
        except OSError as error:
            assert error.errno == errno.ENOENT
        else:
            raise AssertionError("watching a missing path succeeded")
