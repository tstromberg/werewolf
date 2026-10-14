"""Authenticate and round-trip a persistent message using AMQP 0-9-1."""
import socket
import struct
import sys


def short(value):
    value = value.encode()
    return bytes([len(value)]) + value


def long(value):
    return struct.pack('!I', len(value)) + value


class Broker:
    def __init__(self, user, password):
        self.connection = socket.create_connection(('127.0.0.1', 5672), timeout=5)
        self.connection.sendall(b'AMQP\0\0\x09\x01')
        self.method(10, 10)
        response = b'\0' + user.encode() + b'\0' + password.encode()
        self.send_method(0, 10, 11, b'\0' * 4 + short('PLAIN') + long(response) + short('en_US'))
        self.method(10, 30)
        self.send_method(0, 10, 31, struct.pack('!HIH', 1, 131072, 0))
        self.send_method(0, 10, 40, short('/') + short('') + b'\0')
        self.method(10, 41)
        self.send_method(1, 20, 10, short(''))
        self.method(20, 11)

    def receive(self, size):
        result = bytearray()
        while len(result) < size:
            part = self.connection.recv(size - len(result))
            if not part:
                raise RuntimeError('broker closed the connection')
            result += part
        return bytes(result)

    def frame(self):
        kind, channel, length = struct.unpack('!BHI', self.receive(7))
        if length > 131072:
            raise RuntimeError('oversized AMQP frame')
        payload = self.receive(length)
        if self.receive(1) != b'\xce':
            raise RuntimeError('invalid AMQP frame end')
        return kind, channel, payload

    def method(self, class_id, method_id):
        kind, _, payload = self.frame()
        if kind != 1 or payload[:4] != struct.pack('!HH', class_id, method_id):
            raise RuntimeError('unexpected AMQP method: ' + repr(payload[:100]))
        return payload[4:]

    def send(self, kind, channel, payload):
        self.connection.sendall(struct.pack('!BHI', kind, channel, len(payload)) + payload + b'\xce')

    def send_method(self, channel, class_id, method_id, payload=b''):
        self.send(1, channel, struct.pack('!HH', class_id, method_id) + payload)

    def queue(self, name):
        self.send_method(1, 50, 10, b'\0\0' + short(name) + b'\x02' + b'\0' * 4)
        self.method(50, 11)

    def publish(self, name, body):
        self.send_method(1, 60, 40, b'\0\0' + short('') + short(name) + b'\0')
        self.send(2, 1, struct.pack('!HHQHB', 60, 0, len(body), 0x1000, 2))
        self.send(3, 1, body)

    def get(self, name):
        self.send_method(1, 60, 70, b'\0\0' + short(name) + b'\x01')
        self.method(60, 71)
        kind, _, header = self.frame()
        if kind != 2 or len(header) < 14:
            raise RuntimeError('missing message header')
        length = struct.unpack('!Q', header[4:12])[0]
        if length > 1048576:
            raise RuntimeError('oversized message')
        body = bytearray()
        while len(body) < length:
            kind, _, part = self.frame()
            if kind != 3 or not part:
                raise RuntimeError('missing message body')
            body += part
        return bytes(body)


if '--guest' in sys.argv:
    try:
        broker = Broker('guest', 'guest')
    except (OSError, RuntimeError):
        print('rabbitmq-probe: guest refused')
    else:
        broker.connection.close()
        raise RuntimeError('default guest login succeeded')
else:
    broker = Broker('app', 'werewolf-check-pass-1')
    if '--retained' in sys.argv:
        if broker.get('werewolf-retained') != b'werewolf-kept-message':
            raise RuntimeError('persistent message was lost')
    else:
        broker.queue('werewolf-probe')
        broker.send_method(1, 50, 30, b'\0\0' + short('werewolf-probe') + b'\0')
        broker.method(50, 31)
        broker.publish('werewolf-probe', b'werewolf-amqp-check')
        if broker.get('werewolf-probe') != b'werewolf-amqp-check':
            raise RuntimeError('AMQP message was lost')
        broker.queue('werewolf-retained')
        broker.publish('werewolf-retained', b'werewolf-kept-message')
        # A synchronous method on this channel waits behind the publish.
        broker.queue('werewolf-retained')
    broker.send_method(0, 10, 50, struct.pack('!H', 200) + short('done') + b'\0' * 4)
    broker.method(10, 51)
    broker.connection.close()
    print('rabbitmq-probe: authenticated delivery passed')
