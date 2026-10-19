"""Use a publisher's recorded transport for host-side integration assertions."""
import http.client
import importlib.machinery
import importlib.util
import json
from pathlib import Path
import ssl


loader = importlib.machinery.SourceFileLoader(
    'test_publisher_transport', str(Path(__file__).resolve().parent.parent / 'tools/local-publisher'))
spec = importlib.util.spec_from_loader(loader.name, loader)
publisher = importlib.util.module_from_spec(spec)
loader.exec_module(publisher)


def connection(config, timeout=10):
    if config.get('service'):
        config = json.loads((Path(config['service']) / 'publisher.json').read_text())
    context = ssl.create_default_context(cafile=config['certificate'])
    if config.get('private'):
        stream = publisher.PrivateConnection(config, context)
        stream.timeout = timeout
        return stream
    return http.client.HTTPSConnection('127.0.0.1', config['port'], context=context, timeout=timeout)
