"""Exercise the confined adapter over D-Bus, using only Python's stdlib."""
import argparse
import os
import pwd
import socket
import struct


BUS = "org.freedesktop.DBus"
SYSTEMD = "org.freedesktop.systemd1"
MANAGER = SYSTEMD + ".Manager"
ROOT = "/org/freedesktop/systemd1"
PROPERTIES = BUS + ".Properties"
SOCKET = "/data/share/unifi/bus/system_bus_socket"


class Writer:
    def __init__(self):
        self.data = bytearray()

    def align(self, n):
        self.data.extend(bytes(-len(self.data) % n))

    def uint(self, n):
        self.align(4)
        self.data.extend(struct.pack("<I", n))

    def string(self, value, kind="s"):
        value = value.encode()
        if kind == "g":
            self.data.append(len(value))
        else:
            self.uint(len(value))
        self.data.extend(value + b"\0")

    def field(self, code, kind, value):
        self.align(8)
        self.data.append(code)
        self.string(kind, "g")
        if kind == "u":
            self.uint(value)
        else:
            self.string(value, kind)


class Reader:
    def __init__(self, data):
        self.data, self.pos = data, 0

    def align(self, n):
        self.pos += -self.pos % n

    def take(self, n):
        if self.pos + n > len(self.data):
            raise AssertionError("truncated response")
        result = self.data[self.pos:self.pos + n]
        self.pos += n
        return result

    def uint(self):
        self.align(4)
        return struct.unpack("<I", self.take(4))[0]

    def string(self, kind="s"):
        n = self.take(1)[0] if kind == "g" else self.uint()
        result = self.take(n)
        assert self.take(1) == b"\0"
        return result.decode()


class Client:
    def __init__(self, bad_auth=False):
        self.socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.socket.settimeout(3)
        identity = pwd.getpwnam("_oci-unifi-core")
        peer_uid = identity.pw_uid
        original_uid = os.geteuid()
        original_gid = os.getegid()
        try:
            os.setegid(identity.pw_gid)
            os.seteuid(peer_uid)
            self.socket.connect(SOCKET)
        finally:
            os.seteuid(original_uid)
            os.setegid(original_gid)
        self.stream = self.socket.makefile("rb", buffering=0)
        self.serial = 0
        uid = "0" if bad_auth else str(peer_uid)
        self.socket.sendall(b"\0AUTH EXTERNAL " + uid.encode().hex().encode() + b"\r\n")
        line = self.stream.readline(128)
        if bad_auth:
            assert line == b"REJECTED EXTERNAL\r\n", line
            return
        assert line.startswith(b"OK "), line
        self.socket.sendall(b"BEGIN\r\n")
        response = self.call(BUS, "/org/freedesktop/DBus", BUS, "Hello")
        assert response[0] == 2

    def close(self):
        self.stream.close()
        self.socket.close()

    def read(self, n):
        result = bytearray()
        while len(result) < n:
            part = self.stream.read(n - len(result))
            assert part, "adapter closed connection"
            result.extend(part)
        return bytes(result)

    def call(self, destination, path, interface, member, signature="", values=()):
        self.serial += 1
        fields, body = Writer(), Writer()
        for code, kind, value in [(1, "o", path), (2, "s", interface),
                                  (3, "s", member), (6, "s", destination)]:
            fields.field(code, kind, value)
        if signature:
            fields.field(8, "g", signature)
        for value in values:
            body.string(value)
        fixed = struct.pack("<BBBBIII", ord("l"), 1, 0, 1, len(body.data),
                            self.serial, len(fields.data))
        padding = bytes(-(16 + len(fields.data)) % 8)
        self.socket.sendall(fixed + fields.data + padding + body.data)
        header = self.read(16)
        endian, kind, _, version, body_len, _, fields_len = struct.unpack("<BBBBIII", header)
        assert endian == ord("l") and version == 1
        assert body_len < 32768 and fields_len < 32768
        fields = Reader(header + self.read(fields_len))
        fields.pos = 16
        headers = {}
        while fields.pos < len(fields.data):
            fields.align(8)
            code = fields.take(1)[0]
            field_type = fields.string("g")
            headers[code] = fields.uint() if field_type == "u" else fields.string(field_type)
        self.read(-(16 + fields_len) % 8)
        response = Reader(self.read(body_len))
        assert headers[5] == self.serial, headers
        assert headers[7] in (BUS, ":1.0"), headers
        return kind, headers, response


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--control", action="store_true")
    parser.add_argument("--unknown-unit", action="store_true")
    parser.add_argument("--bad-auth", action="store_true")
    parser.add_argument("--wrong-peer", action="store_true")
    options = parser.parse_args()
    if options.wrong_peer:
        # Even a client claiming Core's UID must have Core's kernel UID.
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as peer:
            peer.settimeout(3)
            try:
                peer.connect(SOCKET)
                uid = str(pwd.getpwnam("_oci-unifi-core").pw_uid).encode().hex().encode()
                peer.sendall(b"\0AUTH EXTERNAL " + uid + b"\r\n")
                assert peer.recv(128) == b"", "another UID authenticated as Core"
            except (PermissionError, ConnectionResetError, BrokenPipeError):
                pass
        return
    client = Client(options.bad_auth)
    try:
        if options.bad_auth:
            return
        if options.control:
            kind, headers, _ = client.call(SYSTEMD, ROOT, MANAGER, "RestartUnit", "ss",
                                           ("unifi.service", "replace"))
            assert kind == 3 and headers[4] == BUS + ".Error.AccessDenied", headers
            return
        if options.unknown_unit:
            kind, headers, _ = client.call(SYSTEMD, ROOT, MANAGER, "LoadUnit", "s",
                                           ("sshd.service",))
            assert kind == 3 and headers[4] == SYSTEMD + ".NoSuchUnit", headers
            return
        kind, _, body = client.call(SYSTEMD, ROOT, MANAGER, "LoadUnit", "s", ("unifi.service",))
        assert kind == 2
        path = body.string()
        assert path == ROOT + "/unit/unifi_2eservice", path
        kind, _, body = client.call(SYSTEMD, path, PROPERTIES, "Get", "ss",
                                    (SYSTEMD + ".Unit", "ActiveState"))
        assert kind == 2 and body.string("g") == "s"
        assert body.string() in ("active", "activating", "deactivating", "inactive")
        kind, _, body = client.call(SYSTEMD, path, PROPERTIES, "Get", "ss",
                                    (SYSTEMD + ".Service", "StatusText"))
        assert kind == 2 and body.string("g") == "s" and body.string() == ""
    finally:
        client.close()


if __name__ == "__main__":
    main()
