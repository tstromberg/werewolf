"""Compare durable console identity and certificates across VM boots."""
import hashlib
import json
import os
from pathlib import Path
import sys
import uuid


STATE = Path('/data/.unifi-identity-check')
IDENTITY = Path('/data/svc/unifi-core/unifi-core/uuid')
TLS = Path('/data/share/unifi/config/tls')

identity = IDENTITY.read_text()
assert str(uuid.UUID(identity, version=5)) == identity
assert IDENTITY.stat().st_mode & 0o777 == 0o600
certificates = {}
for name in ['unifi-core.crt']:
    data = (TLS / name).read_bytes()
    assert b'-----BEGIN CERTIFICATE-----' in data
    certificates[name] = hashlib.sha256(data).hexdigest()
for name in ['unifi-core.key', 'unifi-core-direct.key']:
    assert not (TLS / name).stat().st_mode & 0o007, 'TLS key accessible to other users'
current = {'uuid': identity, 'certificates': certificates}
if '--retained' in sys.argv:
    assert current == json.loads(STATE.read_text()), 'console identity or TLS certificates changed'
else:
    descriptor = os.open(STATE, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, 'w') as output:
        json.dump(current, output)
        output.flush()
        os.fsync(output.fileno())
print('unifi-persistence: identity and TLS certificates',
      'retained' if '--retained' in sys.argv else 'recorded')
