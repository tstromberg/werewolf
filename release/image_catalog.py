"""The signed catalog of every form's protected targets. No bucket listing is public."""
import hashlib
import html
import json
from pathlib import Path
import re
import subprocess
import tempfile
import urllib.error
import urllib.request

ARCHES = ('aarch64', 'x86_64')
# A provider's gateway is baked into the verified root, so each is its own
# image. Lima is arm64 only.
PROVIDERS = {'aarch64': ('lima', 'qemu'), 'x86_64': ('qemu',)}
PUBLIC = json.loads(Path(__file__).with_name('protected').joinpath('trust.json').read_text())['source']
FORMAT = 'werewolf-form-catalog/1'
HEX = re.compile(r'[0-9a-f]{64}\Z')
NAME = re.compile(r'[a-z][a-z0-9-]{0,63}\Z')
PUBLISHED = 'published'
UNGATED = 'passed; not published: no lifecycle gates for this form'
NO_RUNNER = 'passed; not published: no gate runner for this target'
# Unchanged inputs in these states need no rebuild; failures retry every run.
SETTLED = {PUBLISHED, UNGATED, NO_RUNNER}


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


def namespace(form, provider, arch):
    if not NAME.fullmatch(form) or provider not in PROVIDERS.get(arch, ()):
        raise ValueError('invalid form image target')
    return '/'.join((form, provider, arch))


def verify_signature(data, signature, certificate):
    if len(data) > 4 << 20 or len(signature) not in (256, 384, 512):
        raise ValueError('invalid signed image metadata size')
    with tempfile.TemporaryDirectory(prefix='ww-image-signature-') as temporary:
        root = Path(temporary)
        (root / 'data').write_bytes(data)
        (root / 'signature').write_bytes(signature)
        (root / 'key').write_bytes(subprocess.check_output(
            ['openssl', 'x509', '-in', str(certificate), '-pubkey', '-noout']))
        subprocess.run(['openssl', 'dgst', '-sha256', '-verify', str(root / 'key'),
                        '-signature', str(root / 'signature'), str(root / 'data')],
                       check=True, capture_output=True)


def sign(data, key):
    return subprocess.check_output(['openssl', 'dgst', '-sha256', '-sign', str(key)], input=data)


def envelope(data, key):
    raw = encode(data)
    return encode(dict(manifest=raw.decode(), signature=sign(raw, key).hex()))


def validate(row):
    fields = {'form', 'provider', 'arch', 'status', 'run', 'summary', 'guide', 'inputs', 'latest'}
    if not {'form', 'provider', 'arch', 'status'} <= set(row) <= fields:
        raise ValueError('invalid form catalog row')
    key = namespace(row['form'], row['provider'], row['arch'])
    if not all(isinstance(row.get(k, ''), str) and row.get(k, '').isprintable()
               for k in ('status', 'run', 'summary', 'guide')):
        raise ValueError('invalid form catalog text')
    if 'inputs' in row and not HEX.fullmatch(row['inputs']):
        raise ValueError('invalid form catalog inputs')
    if 'latest' in row:
        latest = row['latest']
        if set(latest) != {'serial', 'commit', 'descriptor', 'object', 'size'} or \
                not re.fullmatch(r'[0-9]{8}T[0-9]{6}Z', latest['serial']) or \
                not re.fullmatch(r'[0-9a-f]{40}', latest['commit']) or not HEX.fullmatch(latest['descriptor']) or \
                latest['object'] != key + '/objects/' + latest['descriptor'] or type(latest['size']) is not int:
            raise ValueError('invalid published form image')
    return row


def open_index(raw, certificate):
    """The rows of a signed index, keyed by target."""
    head = json.loads(raw)
    if set(head) != {'manifest', 'signature'}:
        raise ValueError('invalid signed form catalog')
    verify_signature(head['manifest'].encode(), bytes.fromhex(head['signature']), certificate)
    catalog = json.loads(head['manifest'])
    if set(catalog) != {'format', 'forms'} or catalog['format'] != FORMAT:
        raise ValueError('invalid form catalog')
    rows = {}
    for row in catalog['forms']:
        key = (row['form'], row['provider'], row['arch'])
        if key in rows:
            raise ValueError('duplicate form catalog row')
        rows[key] = validate(row)
    return rows


def read_index(certificate):
    """The public index, or nothing before the first publication."""
    request = urllib.request.Request(PUBLIC + '/index.json', headers={'User-Agent': 'Werewolf-form-images/1'})
    try:
        with urllib.request.urlopen(request, timeout=45) as response:
            raw = response.read((4 << 20) + 1)
    except urllib.error.HTTPError as error:
        if error.code == 404:
            return {}
        raise
    if len(raw) > 4 << 20:
        raise ValueError('form catalog is too large')
    return open_index(raw, certificate)


def page(rows, title='Werewolf images'):
    body = ['<!doctype html><html lang="en"><meta charset="utf-8">',
            '<meta name="viewport" content="width=device-width,initial-scale=1">',
            '<title>' + html.escape(title) + '</title>',
            '<style>body{font:16px system-ui;max-width:80rem;margin:2rem auto;padding:0 1rem}'
            'table{border-collapse:collapse;width:100%}th,td{text-align:left;padding:.6rem;border-bottom:1px solid #bbb}'
            'a{color:#1265ac}small{display:block}code{overflow-wrap:anywhere}</style>',
            '<h1>' + html.escape(title) + '</h1>',
            '<p>Every form is built twice with every protection: signed UEFI boot, IPE, a verified root '
            'and TPM-anchored A/B updates. A target is published only when its exact bundle has passed '
            'all fourteen lifecycle gates; a failed build or gate keeps the previous release.</p>',
            '<p><code>howl run --with FORM</code> downloads, verifies and enrolls a published image. '
            'Its qcow2 boots only through that enrollment. '
            '<a href="https://github.com/werewolf-linux/werewolf/blob/main/docs/form-images.md">'
            'How images are built and verified</a>.</p>',
            '<p><a href="' + PUBLIC + '/index.html">All forms</a> · '
            '<a href="' + PUBLIC + '/index.json">Signed JSON catalog</a></p>',
            '<table><thead><tr><th>Form</th><th>Target</th><th>Latest published image</th>'
            '<th>Latest attempt</th></tr></thead><tbody>']
    for row in rows:
        validate(row)
        form = row['form']
        guide = row.get('guide') or 'https://github.com/werewolf-linux/werewolf/tree/main/forms/' + form
        latest = row.get('latest')
        links = 'Not published'
        if latest:
            base = PUBLIC + '/' + latest['object']
            links = '<a href="' + base + '/disk.qcow2">qcow2</a> · ' + \
                '<a href="' + base + '/release-notes.html">release notes</a> · ' + \
                '<a href="' + base + '/downloads.json">manifest</a> · ' + \
                '<a href="' + base + '/downloads.json.sig">signature</a> · ' + \
                '<a href="' + base + '/gates.json">gates</a> · ' + \
                '<a href="' + base + '/tests.json">tests</a>' + \
                '<small>' + latest['serial'] + ' · ' + str(round(latest['size'] / (1 << 20), 1)) + ' MiB</small>'
        status = html.escape(row['status'])
        if row.get('run'):
            status = '<a href="' + html.escape(row['run'], quote=True) + '">' + status + '</a>'
        body.append('<tr><td><a href="' + PUBLIC + '/' + form + '/index.html">' + form + '</a>'
                    '<small>' + html.escape(row.get('summary', '')) + '</small>'
                    '<small><a href="' + html.escape(guide, quote=True) + '">Setup guide</a></small></td><td>' +
                    row['provider'] + '/' + row['arch'] + '</td><td>' + links + '</td><td>' + status + '</td></tr>')
    return '\n'.join(body + ['</tbody></table></html>']) + '\n'
