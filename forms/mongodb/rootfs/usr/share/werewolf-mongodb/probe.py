"""Exercise MongoDB OP_MSG without adding a database client to the image."""
import socket
import struct
import sys


def bson(document):
    fields = bytearray()
    for key, value in document.items():
        name = key.encode() + b'\0'
        if isinstance(value, bool):
            fields += b'\x08' + name + bytes([value])
        elif isinstance(value, str):
            encoded = value.encode() + b'\0'
            fields += b'\x02' + name + struct.pack('<i', len(encoded)) + encoded
        elif isinstance(value, int):
            fields += b'\x10' + name + struct.pack('<i', value)
        else:
            kind = b'\x04' if isinstance(value, list) else b'\x03'
            if isinstance(value, list):
                value = {str(i): item for i, item in enumerate(value)}
            fields += kind + name + bson(value)
    return struct.pack('<i', len(fields) + 5) + fields + b'\0'


def receive(connection, length):
    result = bytearray()
    while len(result) < length:
        part = connection.recv(length - len(result))
        if not part:
            raise RuntimeError('MongoDB closed the connection')
        result += part
    return result


def command(document):
    document['$db'] = 'werewolf_check'
    body = struct.pack('<i', 0) + b'\0' + bson(document)
    with socket.create_connection(('127.0.0.1', 27017), timeout=5) as connection:
        connection.sendall(struct.pack('<iiii', len(body) + 16, 1, 0, 2013) + body)
        length, _, response_to, opcode = struct.unpack('<iiii', receive(connection, 16))
        if response_to != 1 or opcode != 2013 or not 21 < length < 1048576:
            raise RuntimeError('invalid MongoDB response')
        reply = receive(connection, length - 16)
        if b'\x01ok\0' + struct.pack('<d', 1.0) not in reply:
            raise RuntimeError('MongoDB command failed')
        return reply


command({'ping': 1})
if '--retained' not in sys.argv:
    command({'update': 'probe', 'updates': [{'q': {'_id': 'werewolf'},
             'u': {'$set': {'value': 'werewolf-wire-check'}}, 'upsert': True}]})
if b'werewolf-wire-check' not in command({'find': 'probe', 'filter': {'_id': 'werewolf'}}):
    raise RuntimeError('MongoDB did not return the stored document')
print('mongodb-probe: ping, write and read passed')
