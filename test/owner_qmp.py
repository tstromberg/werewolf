"""Host-side QEMU controls for real storage-failure lifecycle tests."""
import json
from pathlib import Path
import socket


def command(path, operation, arguments=None):
    with socket.socket(socket.AF_UNIX) as connection:
        connection.settimeout(10)
        connection.connect(str(path))
        with connection.makefile('rwb', buffering=0) as stream:
            greeting = json.loads(stream.readline(1 << 20))
            if 'QMP' not in greeting:
                raise ValueError('missing QMP greeting')
            for identity, name, args in ((1, 'qmp_capabilities', None), (2, operation, arguments)):
                request = dict(execute=name, id=identity)
                if args is not None:
                    request['arguments'] = args
                stream.write(json.dumps(request).encode() + b'\n')
                while True:
                    raw = stream.readline(1 << 20)
                    if not raw or len(raw) >= 1 << 20:
                        raise ValueError('missing or oversized QMP response')
                    response = json.loads(raw)
                    if response.get('id') == identity:
                        break
                if 'error' in response:
                    raise ValueError('QMP refused ' + name + ': ' + str(response['error']))
            return response['return']


class StorageFault:
    """Return EIO for disk writes without editing any image or stopping a service."""
    def __init__(self, path, disk):
        self.path = path
        nodes = command(path, 'query-named-block-nodes')
        roots = [node for node in nodes if node.get('drv') == 'raw' and
                 Path(node.get('file', '/missing')).resolve() == Path(disk).resolve()]
        if len(roots) != 1:
            raise ValueError('cannot identify the owned raw boot disk')
        root = roots[0]
        children = [child['node-name'] for child in root['children'] if child['child'] == 'file']
        if len(children) != 1:
            raise ValueError('boot disk does not have a unique file child')
        self.root, self.file = root['node-name'], children[0]
        self.filter = 'werewolf-storage-fault'
        command(path, 'blockdev-add', dict(driver='blkdebug', image=self.file, **{
            'node-name': self.filter,
            'inject-error': [dict(event='write_aio', iotype='write', errno=5, once=False, immediately=True)],
        }))
        self.attach(self.filter)

    def attach(self, child):
        command(self.path, 'blockdev-reopen', dict(options=[
            dict(driver='raw', file=child, **{'node-name': self.root})]))

    def restore(self):
        self.attach(self.file)
        command(self.path, 'blockdev-del', {'node-name': self.filter})
