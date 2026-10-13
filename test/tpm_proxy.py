"""Proxy QEMU's swtpm control/data sockets to cut one retirement command precisely."""
import array
from pathlib import Path
import socket
import threading


class Proxy:
    def __init__(self, listen, backend, select=None):
        self.backend = str(backend)
        self.path = Path(listen)
        self.listener = socket.socket(socket.AF_UNIX)
        self.listener.bind(str(listen))
        self.listener.listen(2)
        self.listener.settimeout(0.2)
        self.closed = False
        self.connections = []
        self.failures = []
        self.mode = None
        self.select = select
        self.hit = threading.Event()
        self.release = threading.Event()
        self.cancelled = False
        self.thread = threading.Thread(target=self.accept, daemon=True)
        self.thread.start()

    def arm(self, mode):
        self.hit.clear()
        self.release.clear()
        self.cancelled = False
        self.mode = mode

    def cancel(self):
        self.cancelled = True
        self.mode = None
        self.release.set()

    def accept(self):
        while not self.closed:
            try:
                client, _ = self.listener.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            backend = socket.socket(socket.AF_UNIX)
            backend.connect(self.backend)
            self.connections.extend([client, backend])
            for source, target, outbound in [(client, backend, True), (backend, client, False)]:
                threading.Thread(target=self.control, args=(source, target, outbound), daemon=True).start()

    def control(self, source, target, outbound):
        try:
            while not self.closed:
                raw, ancillary, _, _ = source.recvmsg(65536, socket.CMSG_SPACE(16))
                if not raw:
                    return
                passed = []
                for level, kind, data in ancillary:
                    if level != socket.SOL_SOCKET or kind != socket.SCM_RIGHTS or not outbound:
                        raise RuntimeError('unexpected swtpm descriptor message')
                    descriptors = array.array('i')
                    descriptors.frombytes(data[:len(data) - len(data) % descriptors.itemsize])
                    if len(descriptors) != 1:
                        raise RuntimeError('expected one swtpm data descriptor')
                    client_data = socket.socket(fileno=descriptors[0])
                    local, remote = socket.socketpair()
                    self.connections.extend([client_data, local])
                    passed.append((level, kind, array.array('i', [remote.fileno()])))
                    target.sendmsg([raw], passed)
                    remote.close()
                    threading.Thread(target=self.data, args=(client_data, local), daemon=True).start()
                if not ancillary:
                    target.sendall(raw)
        except (OSError, EOFError):
            pass
        except Exception as exc:
            self.failures.append(exc)
            print('tpm proxy control failure: ' + repr(exc), flush=True)
        finally:
            for connection in (source, target):
                try:
                    connection.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass

    @staticmethod
    def packet(stream):
        raw = bytearray()
        expected = 10
        while len(raw) < expected:
            part = stream.recv(expected - len(raw))
            if not part:
                raise EOFError()
            raw.extend(part)
            if len(raw) == 10:
                expected = int.from_bytes(raw[2:6], 'big')
                if not 10 <= expected <= 65536:
                    raise RuntimeError('invalid TPM packet length')
        return bytes(raw)

    def gate(self):
        self.hit.set()
        self.release.wait()
        return self.cancelled or self.closed

    def data(self, client, backend):
        try:
            while not self.closed:
                command = self.packet(client)
                retirement = (int.from_bytes(command[6:10], 'big') == 0x136 and
                              int.from_bytes(command[10:14], 'big') == 0x01500021)
                selected = self.select(command) if self.select else retirement
                mode = self.mode if selected else None
                if mode == 'before' and self.gate():
                    return
                backend.sendall(command)
                response = self.packet(backend)
                if mode == 'after':
                    if int.from_bytes(response[6:10], 'big'):
                        raise RuntimeError('retirement refused before cut')
                    if self.gate():
                        return
                client.sendall(response)
        except (OSError, EOFError):
            pass
        except Exception as exc:
            self.failures.append(exc)
            self.hit.set()
        finally:
            client.close()
            backend.close()

    def close(self):
        self.closed = True
        self.cancel()
        self.listener.close()
        self.path.unlink(missing_ok=True)
        for connection in self.connections:
            try:
                connection.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            connection.close()
        self.thread.join(timeout=2)
