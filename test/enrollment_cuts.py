"""Private native TPM fault injection; never log command buffers containing auth."""
from pathlib import Path
import socket
import struct
import threading


STEPS = {
    'owner': (0x129, 0x40000001),
    'lockout': (0x129, 0x4000000a),
    'clear': (0x127, 0x4000000a),
    'define': (0x12a, 0x40000001),
    'platform': (0x121, 0x4000000c),
    'extend': (0x136, 0x40000001),
}


def selected(command, step):
    code, handle = STEPS[step]
    return len(command) >= 14 and int.from_bytes(command[6:10], 'big') == code and int.from_bytes(command[10:14], 'big') == handle


def packet(stream):
    raw = bytearray()
    size = 10
    while len(raw) < size:
        part = stream.recv(size - len(raw))
        if not part:
            raise EOFError()
        raw.extend(part)
        if len(raw) == 10:
            size = int.from_bytes(raw[2:6], 'big')
            if not 10 <= size <= 4096:
                raise RuntimeError('invalid bounded TPM packet')
    return bytes(raw)


class Cut:
    def __init__(self, filename, backend, step, when):
        self.filename = Path(filename)
        self.backend = str(backend)
        self.step, self.when = step, when
        self.hit = threading.Event()
        self.failures = []
        self.closed = False
        self.connections = []
        self.listener = socket.socket(socket.AF_UNIX)
        self.listener.bind(str(self.filename))
        self.listener.listen(1)
        self.listener.settimeout(.1)
        self.thread = threading.Thread(target=self.serve, daemon=True)
        self.thread.start()

    def serve(self):
        try:
            while not self.closed:
                try:
                    client, _ = self.listener.accept()
                    break
                except socket.timeout:
                    continue
            else:
                return
            with client, socket.socket(socket.AF_UNIX) as backend:
                self.connections += [client, backend]
                backend.connect(self.backend)
                while not self.closed:
                    request = packet(client)
                    match = selected(request, self.step)
                    if match and self.when == 'before':
                        self.hit.set()
                        return
                    backend.sendall(request)
                    reply = packet(backend)
                    if match and self.when == 'after':
                        if int.from_bytes(reply[6:10], 'big') != 0:
                            raise RuntimeError('selected TPM command failed before interruption')
                        self.hit.set()
                        return
                    client.sendall(reply)
        except (OSError, EOFError):
            pass
        except Exception as exc:
            self.failures.append(str(exc))
        finally:
            self.listener.close()

    def close(self):
        self.closed = True
        for connection in self.connections + [self.listener]:
            try:
                connection.close()
            except OSError:
                pass
        self.thread.join(timeout=2)
        self.filename.unlink(missing_ok=True)


def command(endpoint, code, handles=(), params=b'', secret=None):
    body = b''.join(struct.pack('>I', handle) for handle in handles)
    if secret is not None:
        auth = struct.pack('>IHBH', 0x40000009, 0, 0, len(secret)) + secret
        body += struct.pack('>I', len(auth)) + auth
    body += params
    request = struct.pack('>HII', 0x8001 if secret is None else 0x8002, 10 + len(body), code) + body
    with socket.socket(socket.AF_UNIX) as stream:
        stream.settimeout(10)
        stream.connect(str(endpoint))
        stream.sendall(request)
        reply = packet(stream)
    status = int.from_bytes(reply[6:10], 'big')
    return status, reply[10:]


def property_value(endpoint, identifier):
    status, raw = command(endpoint, 0x17a, params=struct.pack('>III', 6, identifier, 1))
    if status or len(raw) != 17 or struct.unpack('>IIII', raw[1:])[:3] != (6, 1, identifier):
        raise RuntimeError('invalid independent TPM property response')
    return int.from_bytes(raw[-4:], 'big')


def snapshot(endpoint):
    permanent = property_value(endpoint, 0x200)
    return permanent & 0x105, public_area(endpoint, 0x01500021), public_area(endpoint, 0x01500020)


def public_area(endpoint, index):
    status, raw = command(endpoint, 0x169, handles=(index,))
    if status:
        # Missing index only; do not treat arbitrary TPM errors as absence.
        if status != 0x18b:
            raise RuntimeError('unexpected NV read-public error: ' + hex(status))
        public = None
    else:
        size = int.from_bytes(raw[:2], 'big')
        public = raw[2:2 + size]
    return public
