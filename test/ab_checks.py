"""Boot evidence required by every provider A/B lifecycle test."""
import json
import re
import struct


def require_updater_status(status):
    """Check the live coordinator, including saved/fs IDs and dormant capabilities."""
    expected = {'Uid': [77] * 4, 'Gid': [77] * 4, 'Threads': [1],
                'NoNewPrivs': [1], 'Seccomp': [2]}
    expected.update({key: [0] for key in ['CapInh', 'CapPrm', 'CapEff', 'CapBnd', 'CapAmb']})
    found = set()
    for line in status.splitlines():
        key, separator, value = line.partition(':')
        if not separator or key not in expected:
            continue
        if key in found:
            raise AssertionError('duplicate updater status field: ' + key)
        found.add(key)
        try:
            values = [int(word, 16 if key.startswith('Cap') else 10) for word in value.split()]
        except ValueError as error:
            raise AssertionError('invalid updater status field: ' + key) from error
        if values != expected[key]:
            raise AssertionError('unsafe updater status field: ' + line)
    if found != set(expected):
        raise AssertionError('missing updater status fields: ' + ', '.join(sorted(set(expected) - found)))


def require_updater_console(console, boots=1):
    """Each fresh boot must attest the checked credentials before its outcome."""
    handovers = re.split(rb'werewolf: up in [^\r\n]*handing over to runit', console)
    if len(handovers) != boots + 1:
        raise AssertionError('unexpected boot count in updater console')
    expected = b'autoupdate: coordinator uid=77 gid=77 caps=0 nnp=1'
    for boot in handovers[1:]:
        credentials = re.findall(rb'autoupdate: coordinator[^\r\n]*', boot)
        if not credentials or any(value != expected for value in credentials):
            raise AssertionError('missing or unsafe updater credentials in boot console')


def require_refused_image_retry(returncode, before, after):
    """A refused command must append a fresh reason to the durable updater log."""
    if returncode != 1:
        raise AssertionError('updater retry did not return a command refusal')
    if not after.startswith(before):
        raise AssertionError('updater audit log changed its existing history')
    previous = json.loads(before.splitlines()[-1])['seq'] if before else 0
    for line in after[len(before):].splitlines():
        record = json.loads(line)
        if (record['seq'] > previous and record.get('event') == 'error' and
                record.get('error') == 'ImageRolledBack'):
            return record
    raise AssertionError('updater retry did not record a fresh ImageRolledBack refusal')


def console_posture_failures(console):
    """Recover a complete posture summary when kernel audits interrupt the UART."""
    clean = re.sub(rb'\[ *[0-9]+\.[0-9]+\] [^\n]*\n', b'', console)
    clean = clean.replace(b'\r', b'').replace(b'\n', b'')
    match = re.search(rb'posture: fail=([a-z0-9,-]*) pass=[0-9]+ skip=[0-9]+ ', clean)
    return set(match[1].decode().split(',')) - {''} if match else None


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
    old_refusal = json.dumps(dict(seq=7, event='error', error='ImageRolledBack')) + '\n'
    new_refusal = json.dumps(dict(seq=8, event='error', error='ImageRolledBack')) + '\n'
    assert require_refused_image_retry(1, old_refusal, old_refusal + new_refusal)['seq'] == 8
    assert require_refused_image_retry(1, '', new_refusal)['seq'] == 8
    wrong_reason = json.dumps(dict(seq=8, event='error', error='NetworkUnavailable')) + '\n'
    for code, log in [(0, old_refusal + new_refusal), (255, old_refusal + new_refusal),
                      (1, old_refusal), (1, old_refusal + old_refusal),
                      (1, old_refusal + wrong_reason), (1, new_refusal)]:
        try:
            require_refused_image_retry(code, old_refusal, log)
        except AssertionError:
            continue
        raise AssertionError('accepted missing, stale or unrelated retry evidence')
    status = ('Uid:\t77\t77\t77\t77\nGid:\t77\t77\t77\t77\nThreads:\t1\n'
              'CapInh:\t0000000000000000\nCapPrm:\t0000000000000000\n'
              'CapEff:\t0000000000000000\nCapBnd:\t0000000000000000\n'
              'CapAmb:\t0000000000000000\nNoNewPrivs:\t1\nSeccomp:\t2\n')
    require_updater_status(status)
    invalid = ['', status + 'Uid:\t77\t77\t77\t77\n']
    for key in ['Uid', 'Gid']:
        for column in range(4):
            values = ['77'] * 4
            values[column] = '0'
            invalid.append(status.replace(key + ':\t77\t77\t77\t77', key + ':\t' + '\t'.join(values)))
    for line in status.splitlines():
        key, _, value = line.partition(':\t')
        invalid.append(status.replace(line + '\n', ''))
        wrong = '1' if key.startswith('Cap') else '2' if key == 'Threads' else '0'
        invalid.append(status.replace(line, key + ':\t' + wrong))
        invalid.append(status.replace(line, key + ':\tnot-a-number'))
    for bad in invalid:
        try:
            require_updater_status(bad)
        except AssertionError:
            continue
        raise AssertionError('accepted unsafe updater status: ' + bad)
    boot = b'werewolf: up in 0.1s, handing over to runit\r\n'
    credentials = b'autoupdate: coordinator uid=77 gid=77 caps=0 nnp=1\r\n'
    require_updater_console(boot + credentials)
    require_updater_console((boot + credentials) * 2, boots=2)
    for console, count in [(b'', 1), (credentials + boot, 1), (boot, 1),
                           (boot + credentials + boot, 2),
                           ((boot + credentials) * 2, 1)]:
        try:
            require_updater_console(console, count)
        except AssertionError:
            continue
        raise AssertionError('accepted missing or stale updater console evidence')
    for old, new in [(b'uid=77', b'uid=0'), (b'gid=77', b'gid=0'),
                     (b'caps=0', b'caps=1'), (b'nnp=1', b'nnp=0')]:
        try:
            require_updater_console(boot + credentials.replace(old, new))
        except AssertionError:
            continue
        raise AssertionError('accepted unsafe updater console evidence')
    expected = {'boot-ipe-enforced', 'boot-rollback-protected'}
    interrupted = (b'posture: fail=bo[    6.82] audit: refusal\r\n'
                   b'ot-ipe-enforced,boot-rollback-protected pass=89 skip=4 {}\r\n')
    assert console_posture_failures(interrupted) == expected
    assert console_posture_failures(b'posture: fail= pass=92 skip=4 {}') == set()
    assert console_posture_failures(b'posture: fail=boot-ipe-enforced pass=89') is None
    assert console_posture_failures(b'[    1.0] audit: posture: fail= pass=99 skip=0 \n') is None
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
    print('pass   provider-ab evidence: fresh boots, exact roots, updater credentials, enforcement and commit state')
