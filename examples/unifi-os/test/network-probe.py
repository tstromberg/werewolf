"""Require ready Network APIs and test the kernel's external ingress lookup."""
import fcntl
import errno
import json
from pathlib import Path
import socket
import struct
import sys
import urllib.request


PRIVATE = {5432, 27017, 5672, 4369, 25672, 11051, 11081, 11083,
           11084, 8081, 8443, 8843, 8880, 6789, 28082}
BOUND_LOCAL = {5432, 27017, 5672, 4369, 25672, 11051, 11081, 11083, 11084, 8081}


def ready():
    with urllib.request.urlopen('http://127.0.0.1:8081/status', timeout=2) as reply:
        body = json.load(reply)
    health = body['meta']
    assert health['rc'] == 'ok', body
    assert all(health.get(name) is True for name in
               ['server_running', 'db_running', 'db_connected']), body
    assert all(health.get(name) is False for name in
               ['db_repairing', 'db_importing']), body


def attribute(kind, data):
    size = len(data) + 4
    return struct.pack('=HH', size, kind) + data + bytes(-size % 4)


def ingress(interface, address, destination, source):
    # RTM_GETROUTE with an input interface asks about an arriving packet,
    # unlike connect() to our own address, which takes the local-output rule.
    body = struct.pack('=8BI', socket.AF_INET, 32, 32, 0, 0, 0, 0, 0, 0)
    body += attribute(1, socket.inet_aton(address))  # RTA_DST
    body += attribute(2, socket.inet_aton('10.0.2.2'))  # QEMU gateway
    body += attribute(3, struct.pack('=I', interface))  # RTA_IIF
    body += attribute(27, bytes([socket.IPPROTO_TCP]))  # RTA_IP_PROTO
    body += attribute(28, struct.pack('!H', source))  # RTA_SPORT
    body += attribute(29, struct.pack('!H', destination))  # RTA_DPORT
    header = struct.pack('=IHHII', 16 + len(body), 26, 1, 1, 0)
    with socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, socket.NETLINK_ROUTE) as route:
        route.settimeout(2)
        route.sendto(header + body, (0, 0))
        reply, peer = route.recvfrom(8192)
    assert peer[0] == 0 and len(reply) >= 20, 'invalid routing reply'
    length, kind, _, sequence, _ = struct.unpack_from('=IHHII', reply)
    assert sequence == 1 and 20 <= length <= len(reply)
    if kind == 2:  # NLMSG_ERROR; blackhole lookups return EINVAL.
        return struct.unpack_from('=i', reply, 16)[0]
    assert kind == 24 and length >= 28, (kind, length)  # RTM_NEWROUTE
    return reply[23]  # rtm_type, RTN_LOCAL is 2


ready()
if '--private' not in sys.argv:
    print('unifi-network: status API ready')
    sys.exit(0)

listeners = {}
for line in Path('/proc/net/tcp').read_text().splitlines()[1:]:
    fields = line.split()
    if fields[3] != '0A':
        continue
    address, port = fields[1].split(':')
    address = socket.inet_ntoa(struct.pack('<I', int(address, 16)))
    listeners.setdefault(int(port, 16), set()).add(address)
assert {8080, 8081, 28082} <= listeners.keys(), 'required Network listeners missing'
for port in BOUND_LOCAL & listeners.keys():
    assert listeners[port] == {'127.0.0.1'}, (port, listeners[port])

addresses = set()
with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as interface:
    for index, name in socket.if_nameindex():
        try:
            response = fcntl.ioctl(interface.fileno(), 0x8915, struct.pack('256s', name.encode()))
        except OSError:
            continue
        address = socket.inet_ntoa(response[20:24])
        if not address.startswith('127.'):
            addresses.add((index, address))
assert addresses, 'no non-loopback address available to test exposure'
for index, address in addresses:
    for source in [5432, 8081, 40000]:
        assert ingress(index, address, 443, source) == 2, 'public HTTPS ingress refused'
for port in PRIVATE & listeners.keys():
    with socket.create_connection(('127.0.0.1', port), timeout=1):
        pass
    for index, address in addresses:
        for source in [5432, 8081, 40000]:
            result = ingress(index, address, port, source)
            assert result in {-errno.EINVAL, -errno.EACCES, -errno.ENETUNREACH,
                              -errno.EHOSTUNREACH}, (address, port, source, result)
print('unifi-network: kernel refuses external ingress to private ports, including forged replies')
