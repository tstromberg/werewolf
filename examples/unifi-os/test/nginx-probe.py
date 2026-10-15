"""Exercise the actual nginx reload boundary, using only Python's stdlib."""
import argparse
import os
import pwd
import socket
import time
from pathlib import Path


SOCKET = '/data/share/unifi/reload/nginx.sock'


def request(packet, core=True):
    identity = pwd.getpwnam('_oci-unifi-core')
    uid, gid = os.geteuid(), os.getegid()
    client = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    client.settimeout(6)
    try:
        if core:
            os.setegid(identity.pw_gid)
            os.seteuid(identity.pw_uid)
        client.connect(SOCKET)
    finally:
        os.seteuid(uid)
        os.setegid(gid)
    with client:
        try:
            client.sendall(packet)
            return client.recv(64)
        except (ConnectionResetError, BrokenPipeError):
            return b''


def workers():
    result = set()
    for entry in Path('/proc').iterdir():
        if not entry.name.isdigit():
            continue
        try:
            command = (entry / 'cmdline').read_bytes()
        except (OSError, ProcessLookupError):
            continue
        if command.startswith(b'nginx: worker process'):
            result.add(int(entry.name))
    return result


parser = argparse.ArgumentParser()
parser.add_argument('case', choices=['reload', 'invalid-config', 'denied', 'peer', 'private'])
case = parser.parse_args().case
if case == 'reload':
    before = workers()
    assert before, 'nginx has no workers'
    assert request(b'reload\n') == b'ok\n'
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        after = workers()
        if after and after - before:
            break
        time.sleep(0.1)
    else:
        raise AssertionError('reload did not replace workers')
elif case == 'invalid-config':
    path = Path('/data/share/unifi/config/http/upstream-uos.conf')
    original = path.read_bytes()
    before = workers()
    assert before, 'nginx has no workers'

    def write_as_core(data):
        identity = pwd.getpwnam('_oci-unifi-core')
        uid, gid = os.geteuid(), os.getegid()
        try:
            os.setegid(identity.pw_gid)
            os.seteuid(identity.pw_uid)
            path.write_bytes(data)
        finally:
            os.seteuid(uid)
            os.setegid(gid)

    try:
        write_as_core(original + b'\nwerewolf_invalid_directive;\n')
        assert request(b'reload\n') == b'failed\n', 'invalid configuration accepted'
        assert before <= workers(), 'invalid configuration replaced running workers'
    finally:
        write_as_core(original)
    assert request(b'reload\n') == b'ok\n', 'reload did not recover after configuration repair'
elif case == 'denied':
    for packet in [b'stop\n', b'reload\nextra', b'reload\0', b'x' * 128]:
        assert request(packet) == b'denied\n', packet
elif case == 'peer':
    assert request(b'reload\n', core=False) == b''
elif case == 'private':
    identity = pwd.getpwnam('nginx')
    core = pwd.getpwnam('_oci-unifi-core')
    os.setgroups([core.pw_gid])
    os.setgid(identity.pw_gid)
    os.setuid(identity.pw_uid)
    try:
        Path('/data/svc/unifi-core').iterdir().__next__()
    except PermissionError:
        pass
    else:
        raise AssertionError('nginx can read private Core data')
    try:
        os.open('/data/share/unifi/config/http/upstream-uos.conf', os.O_WRONLY)
    except PermissionError:
        pass
    else:
        raise AssertionError('nginx can rewrite Core configuration')
print('nginx boundary:', case, 'passed')
