"""Boot evidence required by every provider A/B lifecycle test."""
import re
import struct


def require_native_initrd(uki, stage0):
    """The signed native UKI carries stage0, which verifies its external root."""
    pe = struct.unpack_from('<I', uki, 0x3c)[0]
    if uki[:2] != b'MZ' or uki[pe:pe + 4] != b'PE\0\0':
        raise AssertionError('invalid native UKI')
    sections = struct.unpack_from('<H', uki, pe + 6)[0]
    optional = struct.unpack_from('<H', uki, pe + 20)[0]
    matches = []
    for index in range(sections):
        header = pe + 24 + optional + index * 40
        if uki[header:header + 8].rstrip(b'\0') != b'.initrd':
            continue
        size = struct.unpack_from('<I', uki, header + 8)[0]
        offset = struct.unpack_from('<I', uki, header + 20)[0]
        matches.append(uki[offset:offset + size])
    if matches != [stage0]:
        raise AssertionError('native UKI initrd differs from the exported stage0')


def require_boot(value, release, slot, root_hash, previous=None, secure=True, committed=True):
    if not isinstance(value, dict):
        raise AssertionError('missing structured guest evidence')
    boot = value.get('boot_id', '')
    if not isinstance(boot, str) or not re.fullmatch(r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}', boot):
        raise AssertionError('invalid boot ID')
    if boot == previous:
        raise AssertionError('stale evidence from the previous boot')
    if value.get('release') != release or value.get('slot') != slot:
        raise AssertionError('wrong release or slot')
    if value.get('root_hash') != root_hash:
        raise AssertionError('wrong authenticated root')
    for flag in ['verified_root', 'ipe']:
        if value.get(flag) is not True:
            raise AssertionError(flag + ' is not enforced')
    if secure and value.get('secure_boot') is not True:
        raise AssertionError('Secure Boot is not enforced outside setup mode')
    if value.get('committed') is not committed:
        raise AssertionError('unexpected health-commit state')
    return boot


if __name__ == '__main__':
    good = {'boot_id': '12345678-1234-1234-1234-123456789abc', 'release': 'B',
            'slot': 'b', 'root_hash': 'a' * 64, 'verified_root': True,
            'ipe': True, 'secure_boot': True, 'committed': True}
    assert require_boot(good, 'B', 'b', 'a' * 64) == good['boot_id']
    cases = [('boot_id', ''), ('release', 'A'), ('slot', 'a'), ('root_hash', 'b' * 64),
             ('verified_root', False), ('ipe', False), ('secure_boot', False),
             ('committed', False), ('secure_boot', 'true')]
    for field, value in cases:
        bad = dict(good, **{field: value})
        try:
            require_boot(bad, 'B', 'b', 'a' * 64)
        except AssertionError:
            continue
        raise AssertionError('accepted invalid ' + field)
    try:
        require_boot(good, 'B', 'b', 'a' * 64, previous=good['boot_id'])
    except AssertionError:
        pass
    else:
        raise AssertionError('accepted stale boot evidence')
    assert require_boot(dict(good, secure_boot=False), 'B', 'b', 'a' * 64, secure=False)
    assert require_boot(dict(good, committed=False), 'B', 'b', 'a' * 64, committed=False)
    print('pass   provider-ab evidence: fresh boots, exact roots, enforcement and commit state')
