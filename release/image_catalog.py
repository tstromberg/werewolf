"""Signed form-image heads and a static R2 catalog. No bucket listing is public."""
import datetime
import hashlib
import html
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import urllib.error
import urllib.request

import image_notes as notes

ARCHES = ('aarch64', 'x86_64')
PUBLIC = 'https://dist.werewolf-linux.org/images/v1'
ENDPOINT = 'https://c860af766754fb92eec27bc723e6db5d.r2.cloudflarestorage.com'
CHECKS = {'coverage', 'integration', 'production_boot', 'release_disk', 'reproducible'}
HEX = re.compile(r'[0-9a-f]{64}\Z')
NAME = re.compile(r'[a-z][a-z0-9-]{0,63}\Z')
ASSETS = {'disk.qcow2', 'vmlinuz', 'root.erofs', 'stage0.zst', 'cmdline',
          'uki.efi', 'boot.crt', 'latest.json', 'latest.json.sig', 'inputs.tar.gz', 'packages.json'}
RELEASE_ASSETS = {'tests.json', 'release-notes.json', 'release-notes.html'}


def descriptions(path='docs/forms-catalog.md'):
    result = {}
    for line in Path(path).read_text().splitlines():
        match = re.fullmatch(r'\| \[([a-z][a-z0-9-]*)\]\(\.\./([^)]*)\) \| (.*) \|', line)
        if match:
            name, guide, summary = match.groups()
            result[name] = dict(summary=summary, guide='https://github.com/werewolf-linux/werewolf/blob/main/' + guide)
    return result


def encode(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':')) + '\n').encode()


def sha(path):
    value = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for block in iter(lambda: stream.read(1 << 20), b''):
            value.update(block)
    return value.hexdigest()


def record(path):
    path = Path(path)
    if path.is_symlink() or not path.is_file():
        raise ValueError('image assets must be regular files')
    return dict(sha256=sha(path), size=path.stat().st_size)


def read(path, limit=1 << 20):
    with Path(path).open('rb') as stream:
        data = stream.read(limit + 1)
    if len(data) > limit:
        raise ValueError('image metadata is too large')
    return data


def identity(form, arch):
    if not NAME.fullmatch(form) or arch not in ARCHES:
        raise ValueError('invalid form image identity')
    return form + '/' + arch


def serial(value):
    if not re.fullmatch(r'[0-9]{8}T[0-9]{6}Z', value):
        raise ValueError('invalid image serial')
    return datetime.datetime.strptime(value, '%Y%m%dT%H%M%SZ').replace(tzinfo=datetime.timezone.utc)


def public_key(certificate, output):
    output.write_bytes(subprocess.check_output(['openssl', 'x509', '-in', str(certificate), '-pubkey', '-noout']))


def verify_signature(data, signature, certificate):
    if len(data) > 4 << 20 or len(signature) not in (256, 384, 512):
        raise ValueError('invalid signed image metadata size')
    with tempfile.TemporaryDirectory(prefix='ww-image-signature-') as temporary:
        root = Path(temporary)
        (root / 'data').write_bytes(data)
        (root / 'signature').write_bytes(signature)
        public_key(certificate, root / 'key')
        subprocess.run(['openssl', 'dgst', '-sha256', '-verify', str(root / 'key'),
                        '-signature', str(root / 'signature'), str(root / 'data')],
                       check=True, capture_output=True)


def sign(data, key):
    return subprocess.check_output(['openssl', 'dgst', '-sha256', '-sign', str(key)], input=data)


def envelope(data, key):
    raw = encode(data)
    return encode(dict(manifest=raw.decode(), signature=sign(raw, key).hex()))


def open_head(raw, certificate, form, arch):
    if len(raw) > 4 << 20:
        raise ValueError('image head is too large')
    head = json.loads(raw)
    if set(head) != {'manifest', 'signature'}:
        raise ValueError('invalid signed image head')
    verify_signature(head['manifest'].encode(), bytes.fromhex(head['signature']), certificate)
    manifest = json.loads(head['manifest'])
    validate(manifest, form, arch, released=True)
    return manifest


def validate(candidate, form, arch, released=False):
    namespace = identity(form, arch)
    fields = {'format', 'profile', 'form', 'arch', 'serial', 'inputs', 'commit', 'files'}
    if released:
        fields |= {'object', 'checks', 'run'}
    if set(candidate) != fields or candidate['format'] != 'werewolf-form-image/1':
        raise ValueError('invalid form image manifest')
    if candidate['profile'] != 'uefi-ipe/1' or candidate['form'] != form or candidate['arch'] != arch:
        raise ValueError('wrong form image identity or protection profile')
    serial(candidate['serial'])
    if not HEX.fullmatch(candidate['inputs']) or not re.fullmatch(r'[0-9a-f]{40}', candidate['commit']):
        raise ValueError('invalid form image source identity')
    expected = ASSETS | (RELEASE_ASSETS if released else set())
    if set(candidate['files']) != expected:
        raise ValueError('incomplete form image assets')
    for item in candidate['files'].values():
        if set(item) != {'sha256', 'size'} or not HEX.fullmatch(item['sha256']) or \
                type(item['size']) is not int or not 0 < item['size'] <= 16 << 30:
            raise ValueError('invalid form image asset')
    if released:
        if not re.fullmatch(re.escape(namespace) + r'/objects/[0-9a-f]{64}', candidate['object']):
            raise ValueError('invalid immutable image location')
        if set(candidate['checks']) != CHECKS or any(v is not True for v in candidate['checks'].values()):
            raise ValueError('form tests or reproducibility did not pass')
        if not re.fullmatch(r'https://github.com/werewolf-linux/werewolf/actions/runs/[0-9]+', candidate['run']):
            raise ValueError('invalid form image provenance')
    return candidate


def verify_candidate(directory, certificate):
    directory = Path(directory)
    candidate = json.loads(read(directory / 'candidate.json'))
    validate(candidate, candidate['form'], candidate['arch'])
    if {p.name for p in directory.iterdir()} != ASSETS | {'candidate.json'}:
        raise ValueError('unexpected form image assets')
    for name, expected in candidate['files'].items():
        if record(directory / name) != expected:
            raise ValueError('image asset changed: ' + name)
    notes.validate(json.loads(read(directory / 'packages.json', 4 << 20)), candidate['form'], candidate['arch'])
    if (directory / 'boot.crt').read_bytes() != Path(certificate).read_bytes():
        raise ValueError('image boot certificate differs from committed trust')
    raw = read(directory / 'latest.json')
    verify_signature(raw, read(directory / 'latest.json.sig', 512), certificate)
    slot = json.loads(raw)
    if slot['format'] != 'werewolf-image/1' or slot['ipe'] is not True or slot['boot_context'] is not None or \
            slot['channel'] != PUBLIC + '/' + candidate['form'] or \
            any(slot[k] != candidate[k] for k in ('arch', 'serial')):
        raise ValueError('signed update manifest differs from the candidate')
    for name in ('vmlinuz', 'root.erofs', 'stage0.zst', 'cmdline', 'uki.efi'):
        if slot['files'][name] != candidate['files'][name]:
            raise ValueError('signed slot differs from the candidate: ' + name)
    build = hashlib.sha256()
    for name in ('vmlinuz', 'root.erofs', 'stage0.zst', 'cmdline', 'uki.efi'):
        asset = slot['files'][name]
        build.update(('%s %s %d\n' % (name, asset['sha256'], asset['size'])).encode())
    if slot['build'] != build.hexdigest():
        raise ValueError('signed slot has an invalid content identity')
    return candidate, slot


def evidence(report, candidate, candidate_hash):
    if set(report) != {'format', 'form', 'arch', 'inputs', 'candidate', 'checks'} or \
            report['format'] != 'werewolf-form-tests/1' or \
            any(report[k] != candidate[k] for k in ('form', 'arch', 'inputs')) or \
            report['candidate'] != candidate_hash or set(report['checks']) != CHECKS or \
            any(v is not True for v in report['checks'].values()):
        raise ValueError('missing, failed or foreign form test evidence')


class Store:
    def __init__(self, bucket):
        self.bucket = str(bucket).rstrip('/')

    def fetch(self, key, output):
        if not self.bucket.startswith('s3://'):
            source = Path(self.bucket) / key
            if not source.exists():
                return False
            shutil.copyfile(source, output)
            return True
        result = subprocess.run(['aws', 's3', 'cp', '--only-show-errors', '--endpoint-url', ENDPOINT,
                                 self.bucket + '/' + key, str(output)], capture_output=True,
                                env=dict(os.environ, AWS_DEFAULT_REGION='auto'))
        if result.returncode:
            error = result.stderr.decode(errors='replace')
            if '(404)' in error or 'NoSuchKey' in error or 'Not Found' in error:
                return False
            raise ValueError('image store read failed')
        return True

    def upload(self, key, path, immutable=False):
        if self.bucket.startswith('s3://'):
            content_type = 'text/html; charset=utf-8' if key.endswith('.html') else \
                'application/json' if key.endswith('.json') else 'application/octet-stream'
            subprocess.run(['aws', 's3', 'cp', '--only-show-errors', '--endpoint-url', ENDPOINT,
                            '--cache-control', 'public,max-age=31536000,immutable' if immutable else 'no-cache',
                            '--content-type', content_type, str(path), self.bucket + '/' + key],
                           check=True, env=dict(os.environ, AWS_DEFAULT_REGION='auto'))
        else:
            target = Path(self.bucket) / key
            target.parent.mkdir(parents=True, exist_ok=True)
            incoming = target.with_name(target.name + '.new')
            shutil.copyfile(path, incoming)
            os.replace(incoming, target)

    def immutable(self, key, path, temporary):
        if self.fetch(key, temporary):
            if record(temporary) != record(path):
                raise ValueError('immutable image collision: ' + key)
        else:
            self.upload(key, path, True)
        if self.bucket.startswith('s3://'):
            verify_public(key, record(path))


def publish(directory, report, store, key, certificate, run):
    directory = Path(directory)
    candidate, slot = verify_candidate(directory, certificate)
    evidence(report, candidate, sha(directory / 'candidate.json'))
    namespace = identity(candidate['form'], candidate['arch'])
    with tempfile.TemporaryDirectory(prefix='ww-form-publish-') as temporary:
        work = Path(temporary)
        current = work / 'current.json'
        previous = None
        if store.fetch(namespace + '/current.json', current):
            previous = open_head(current.read_bytes(), certificate, candidate['form'], candidate['arch'])
            if candidate['serial'] < previous['serial']:
                raise ValueError('form image publication would roll back')
            if candidate['serial'] == previous['serial']:
                if any(candidate[k] != previous[k] for k in ('inputs', 'commit')) or \
                        any(previous['files'][n] != v for n, v in candidate['files'].items()):
                    raise ValueError('form image serial reused for different bytes')
                for name in ('latest.json.sig', 'latest.json'):
                    store.upload(namespace + '/' + name, directory / name)
                return previous
        (work / 'tests.json').write_bytes(encode(report))
        old_inventory = None
        if previous:
            expected = previous['files']['packages.json']
            if expected['size'] > 4 << 20 or not store.fetch(previous['object'] + '/packages.json', work / 'previous-packages') or \
                    record(work / 'previous-packages') != expected:
                raise ValueError('previous release package inventory is missing or changed')
            old_inventory = json.loads(read(work / 'previous-packages', 4 << 20))
        release_notes = notes.release(candidate, json.loads(read(directory / 'packages.json', 4 << 20)),
                                      previous, old_inventory)
        (work / 'release-notes.json').write_bytes(encode(release_notes))
        (work / 'release-notes.html').write_text(notes.page(release_notes), encoding='utf-8')
        manifest = dict(candidate, files=dict(candidate['files'], **{name: record(work / name) for name in RELEASE_ASSETS}),
                        object=namespace + '/objects/' + sha(directory / 'candidate.json'),
                        checks=report['checks'], run=run)
        validate(manifest, candidate['form'], candidate['arch'], released=True)
        raw = encode(manifest)
        (work / 'downloads.json').write_bytes(raw)
        (work / 'downloads.json.sig').write_bytes(sign(raw, key))
        verify_signature(raw, (work / 'downloads.json.sig').read_bytes(), certificate)
        # No public head or update pointer moves until every immutable file is present.
        for name in sorted(manifest['files'] | {'downloads.json': {}, 'downloads.json.sig': {}}):
            source = directory / name if name in ASSETS else work / name
            store.immutable(manifest['object'] + '/' + name, source, work / 'existing')
        for name in slot['files']:
            if slot['files'][name] is not None:
                store.immutable(namespace + '/' + slot['build'] + '/' + name,
                                directory / name, work / 'existing')
        # One atomic signed envelope is also the durable publication floor. If
        # the updater's JSON/signature pair tears, retry repairs it at this floor.
        current.write_bytes(envelope(manifest, key))
        store.upload(namespace + '/current.json', current)
        for name in ('latest.json.sig', 'latest.json'):
            store.upload(namespace + '/' + name, directory / name)
        return manifest


def read_public(form, arch, certificate):
    url = PUBLIC + '/' + identity(form, arch) + '/current.json'
    try:
        request = urllib.request.Request(url, headers={'User-Agent': 'Werewolf-form-images/1'})
        with urllib.request.urlopen(request, timeout=45) as response:
            raw = response.read((4 << 20) + 1)
    except urllib.error.HTTPError as error:
        if error.code == 404:
            return None
        raise
    head = open_head(raw, certificate, form, arch)
    # A signed receipt can precede an interrupted update-head write. Do not
    # deduplicate that state: a retry must repair the channel before skipping it.
    for name in ('latest.json', 'latest.json.sig'):
        try:
            with urllib.request.urlopen(PUBLIC + '/' + identity(form, arch) + '/' + name, timeout=45) as response:
                data = response.read((1 << 20) + 1)
        except urllib.error.HTTPError as error:
            if error.code == 404:
                return None
            raise
        if dict(sha256=hashlib.sha256(data).hexdigest(), size=len(data)) != head['files'][name]:
            return None
    return head


def verify_public(key, expected):
    value, size = hashlib.sha256(), 0
    request = urllib.request.Request(PUBLIC + '/' + key, headers={'User-Agent': 'Werewolf-form-images/1'})
    with urllib.request.urlopen(request, timeout=120) as response:
        for block in iter(lambda: response.read(1 << 20), b''):
            size += len(block)
            if size > expected['size']:
                raise ValueError('public image exceeds its signed size')
            value.update(block)
    if dict(size=size, sha256=value.hexdigest()) != expected:
        raise ValueError('public image differs from its signed digest')


def page(rows, title='Werewolf images'):
    body = ['<!doctype html><html lang="en"><meta charset="utf-8">',
            '<meta name="viewport" content="width=device-width,initial-scale=1">',
            '<title>' + html.escape(title) + '</title>',
            '<style>body{font:16px system-ui;max-width:80rem;margin:2rem auto;padding:0 1rem}'
            'table{border-collapse:collapse;width:100%}th,td{text-align:left;padding:.6rem;border-bottom:1px solid #bbb}'
            'a{color:#1265ac}small{display:block}code{overflow-wrap:anywhere}</style>',
            '<h1>' + html.escape(title) + '</h1>',
            '<p>Latest passing, reproducible qcow2 images. A failed build or test keeps the previous release.</p>',
            '<p>These images use signed UEFI boot and IPE, with signed A/B slot updates. '
            'They require Secure Boot enrollment and configuration; they do not include '
            'the TPM enrollment of howl’s protected default deployments. '
            '<a href="https://github.com/werewolf-linux/werewolf/blob/main/docs/releases.md#form-image-catalog">'
            'Deployment and verification instructions</a>.</p>',
            '<p><a href="' + PUBLIC + '/index.html">All forms</a> · '
            '<a href="' + PUBLIC + '/index.json">Signed JSON catalog</a></p>',
            '<table><thead><tr><th>Form</th><th>Architecture</th><th>Latest passing image</th>'
            '<th>Latest attempt</th></tr></thead><tbody>']
    for row in rows:
        form, arch = row['form'], row['arch']
        namespace = identity(form, arch)
        guide = row.get('guide') or 'https://github.com/werewolf-linux/werewolf/tree/main/forms/' + form
        latest = row.get('latest')
        links = 'Not published'
        if latest:
            validate(latest, form, arch, released=True)
            base = PUBLIC + '/' + latest['object']
            links = '<a href="' + base + '/disk.qcow2">qcow2</a> · ' + \
                '<a href="' + base + '/release-notes.html">release notes</a> · ' + \
                '<a href="' + base + '/downloads.json">manifest</a> · ' + \
                '<a href="' + base + '/downloads.json.sig">signature</a> · ' + \
                '<a href="' + base + '/tests.json">tests</a>' + \
                '<small>' + html.escape(latest['serial']) + ' · ' + \
                str(round(latest['files']['disk.qcow2']['size'] / (1 << 20), 1)) + ' MiB</small>'
        status = html.escape(row['status'])
        if row.get('run'):
            status = '<a href="' + html.escape(row['run'], quote=True) + '">' + status + '</a>'
        body.append('<tr><td><a href="' + PUBLIC + '/' + form + '/index.html">' + form + '</a>'
                    '<small>' + html.escape(row.get('summary', '')) + '</small>'
                    '<small><a href="' + html.escape(guide, quote=True) + '">Setup guide</a></small></td><td>' + arch +
                    '</td><td>' + links + '<small><a href="' + PUBLIC + '/' + namespace +
                    '/current.json">Latest signed head</a></small></td><td>' + status + '</td></tr>')
    return '\n'.join(body + ['</tbody></table></html>']) + '\n'
