"""Deterministic inventories and package changes for signed form image releases."""
import hashlib
import html
import json
from pathlib import Path
import re

FORMAT = 'werewolf-form-packages/1'
REPOSITORY = 'https://github.com/werewolf-linux/werewolf'
HEX = re.compile(r'[0-9a-f]{64}\Z')
SCOPES = {
    'runtime': 'Image packages',
    'local': 'Packages built from form recipes',
    'kernel': 'Kernel configuration inputs',
    'test': 'Additional integration test packages',
    'build:kernel': 'Kernel build environment',
    'build:stub': 'EFI build environment',
    'boot': 'Boot package inputs',
}


def encode(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':')) + '\n').encode()


def checksum(value):
    return hashlib.sha256(encode(value)).hexdigest()


def inventory(snapshot, form, arch, local=()):
    """Normalize resolved inputs, excluding dev duplicates and other architectures."""
    snapshot = Path(snapshot)
    packages = []
    runtime = {}
    mapping = json.loads((snapshot / 'melange.json').read_text())
    recipe_locks = {value: recipe for recipe, value in mapping.items()}
    for path in sorted([*snapshot.parent.glob('*.lock.json'), *snapshot.glob('*.lock.json')]):
        if path.name == form + '.lock.json':
            scope = 'runtime'
        elif path.name == form + '-dev.lock.json':
            scope = 'test'
        elif path.name in ('kernel.lock.json', 'boot.lock.json'):
            scope = path.name.removesuffix('.lock.json')
        elif path.name in ('kernel-builder.lock.json', 'stub-builder.lock.json'):
            scope = 'build:' + path.name.removesuffix('-builder.lock.json')
        elif path.name in recipe_locks:
            scope = 'build:' + recipe_locks[path.name]
        else:
            raise ValueError('unknown form image package lock: ' + path.name)
        lock = json.loads(path.read_text())
        for package in lock['contents']['packages']:
            if package['architecture'] != arch:
                continue
            # Mirror URLs and resolver ordering are not package content changes.
            content = {key: package[key] for key in ('checksum',) if key in package}
            content.update({key: package[key]['checksum'] for key in ('control', 'data') if key in package})
            if not content:
                raise ValueError('package has no content identity')
            item = dict(scope=scope, name=package['name'], version=package['version'], checksum=checksum(content))
            packages.append(item)
            if scope == 'runtime':
                runtime[item['name']] = (item['version'], item['checksum'])
    packages = [p for p in packages if p['scope'] != 'test' or
                runtime.get(p['name']) != (p['version'], p['checksum'])]
    packages += [dict(scope='local', **package) for package in local]
    lock = json.loads((snapshot / (form + '.lock.json')).read_text())
    images = [dict(form=p['form'], service=p['service'], ref=p['ref'], digest=p['digest'])
              for p in lock['werewolf']['images']]
    result = dict(format=FORMAT, form=form, arch=arch,
                  packages=sorted(packages, key=lambda p: (p['scope'], p['name'])),
                  images=sorted(images, key=lambda p: (p['form'], p['service'])))
    return validate(result, form, arch)


def text(value):
    return isinstance(value, str) and 0 < len(value) <= 4096 and value.isprintable()


def validate(value, form, arch):
    if set(value) != {'format', 'form', 'arch', 'packages', 'images'} or value['format'] != FORMAT or \
            value['form'] != form or value['arch'] != arch:
        raise ValueError('wrong package inventory identity')
    seen = set()
    for package in value['packages']:
        if set(package) != {'scope', 'name', 'version', 'checksum'} or \
                not all(text(package[k]) for k in ('scope', 'name', 'version')) or \
                not HEX.fullmatch(package['checksum']):
            raise ValueError('invalid package inventory entry')
        key = package['scope'], package['name']
        if key in seen:
            raise ValueError('duplicate package inventory entry')
        seen.add(key)
    seen = set()
    for image in value['images']:
        if set(image) != {'form', 'service', 'ref', 'digest'} or not all(text(v) for v in image.values()) or \
                not re.fullmatch(r'.+@sha256:[0-9a-f]{64}', image['digest']):
            raise ValueError('invalid OCI inventory entry')
        key = image['form'], image['service']
        if key in seen:
            raise ValueError('duplicate OCI inventory entry')
        seen.add(key)
    return value


def changes(before, after, keys):
    old = {tuple(p[k] for k in keys): p for p in before}
    new = {tuple(p[k] for k in keys): p for p in after}
    result = []
    for key in sorted(old.keys() | new.keys()):
        left, right = old.get(key), new.get(key)
        if left == right:
            continue
        kind = 'added' if left is None else 'removed' if right is None else 'updated'
        if left and right and 'version' in left and left['version'] == right['version']:
            kind = 'rebuilt'
        result.append(dict(zip(keys, key), kind=kind, before=left, after=right))
    return result


def release(candidate, current, previous=None, old_inventory=None):
    """The baseline is the target's previous published release."""
    form, provider, arch = candidate['form'], candidate['provider'], candidate['arch']
    validate(current, form, arch)
    if previous is not None:
        if not previous['object'].startswith('/'.join((form, provider, arch, 'objects', ''))) or old_inventory is None:
            raise ValueError('release notes need the matching previous package inventory')
        validate(old_inventory, form, arch)
    elif old_inventory is not None:
        raise ValueError('initial release notes cannot have a previous inventory')
    old = old_inventory or dict(packages=[], images=[])
    return dict(format='werewolf-form-release-notes/1', form=form, provider=provider, arch=arch,
                serial=candidate['serial'], commit=candidate['commit'],
                previous={k: previous[k] for k in ('serial', 'commit', 'object')} if previous else None,
                packages=changes(old['packages'], current['packages'], ('scope', 'name')),
                images=changes(old['images'], current['images'], ('form', 'service')))


def page(notes):
    escape = html.escape
    title = ' / '.join((notes['form'], notes['provider'], notes['arch'])) + ' — ' + notes['serial']
    body = ['<!doctype html><html lang="en"><meta charset="utf-8">',
            '<meta name="viewport" content="width=device-width,initial-scale=1">',
            '<title>' + escape(title) + '</title>',
            '<style>body{font:16px system-ui;max-width:80rem;margin:2rem auto;padding:0 1rem}'
            'table{border-collapse:collapse;width:100%}th,td{text-align:left;padding:.6rem;border-bottom:1px solid #bbb}'
            'code{overflow-wrap:anywhere}a{color:#1265ac}</style>',
            '<h1>' + escape(title) + '</h1>',
            '<p><a href="../../../../index.html">Form images</a> · <a href="release-notes.json">JSON changes</a> · '
            '<a href="packages.json">Package inventory</a> · <a href="downloads.json">Signed manifest</a></p>']
    previous = notes['previous']
    if previous:
        body.append('<p>Changes since ' + escape(previous['serial']) +
                    '. <a href="../' + escape(previous['object'].split('/objects/')[1], quote=True) +
                    '/release-notes.html">Previous release notes</a>.</p>')
        if previous['commit'] != notes['commit']:
            body.append('<p><a href="' + REPOSITORY + '/compare/' + previous['commit'] + '...' + notes['commit'] +
                        '">Source comparison</a>.</p>')
    else:
        body.append('<p>Initial published image. Packages and OCI images below establish the baseline.</p>')
    body.append('<p>Resolved package inputs are grouped by use. Build and test packages are not a list of '
                'software installed in the VM. OCI images are compared by digest; their internal packages '
                'are not enumerated. “Rebuilt” means package contents changed at the same version.</p>')
    if not notes['packages'] and not notes['images']:
        body.append('<p>No resolved package or OCI image changes. This release was rebuilt from source, '
                    'build tools or other input changes, or a forced build.</p>')
    scopes = sorted({p['scope'] for p in notes['packages']}, key=lambda s: (s != 'runtime', s))
    for scope in scopes:
        body.append('<h2>' + escape(SCOPES.get(scope, scope.removeprefix('build:') + ' build environment')) + '</h2>')
        body.append('<table><thead><tr><th>Package</th><th>Change</th><th>Previous</th><th>Current</th></tr></thead><tbody>')
        for package in notes['packages']:
            if package['scope'] != scope:
                continue
            versions = [escape(package[side]['version']) if package[side] else '—' for side in ('before', 'after')]
            body.append('<tr><td>' + escape(package['name']) + '</td><td>' + package['kind'] + '</td><td>' +
                        versions[0] + '</td><td>' + versions[1] + '</td></tr>')
        body.append('</tbody></table>')
    if notes['images']:
        body.append('<h2>OCI images</h2>')
        for image in notes['images']:
            body.append('<h3>' + escape(image['form'] + '/' + image['service']) + ' — ' + image['kind'] + '</h3>')
            for label, side in [('Previous', 'before'), ('Current', 'after')]:
                if image[side]:
                    body.append('<p>' + label + ': <code>' + escape(image[side]['digest']) + '</code></p>')
    return '\n'.join(body + ['</html>']) + '\n'
