"""Build, verify and sign explicitly unprotected boot images in the shared flow."""
import hashlib
import importlib.machinery
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile

import image_catalog as catalog
import image_profiles as profiles

FORMAT = 'werewolf-legacy-downloads/1'
FILES = {'disk.qcow2', 'disk.img.zst', 'vmlinuz', 'initramfs.zst', 'cmdline',
         'stage0.zst', 'root.erofs', 'inputs.tar.gz', 'packages.json'}
CHECKS = {'reproducible', 'coverage', 'integration', 'package_update',
          'disk_parity', 'uefi_boot', 'direct_boot'}


def run(*args, **kwargs):
    return subprocess.run([str(arg) for arg in args], check=True, **kwargs)


def write(path, value):
    Path(path).write_bytes(catalog.encode(value))


def validate(manifest, directory):
    profiles.identity(manifest['form'], manifest['arch'], manifest['boot_profile'])
    if manifest['format'] != FORMAT or manifest['boot_profile'] != 'legacy-boot' or \
            manifest['disabled'] != ['secureboot', 'tpm', 'ipe'] or set(manifest['files']) != FILES:
        raise ValueError('invalid legacy boot manifest')
    if not re.fullmatch(r'[0-9]{8}T[0-9]{6}Z', manifest['serial']) or \
            not re.fullmatch(r'[0-9a-f]{40}', manifest['commit']) or \
            not catalog.HEX.fullmatch(manifest['inputs']):
        raise ValueError('invalid legacy release identity')
    if type(manifest['raw_size']) is not int or not 512 << 20 <= manifest['raw_size'] <= 16 << 30:
        raise ValueError('invalid legacy raw disk size')
    for name, expected in manifest['files'].items():
        if catalog.record(Path(directory) / name) != expected:
            raise ValueError('legacy image differs from its manifest: ' + name)
    words = catalog.read(Path(directory) / 'cmdline', 64 << 10).decode().split()
    if any(word.startswith(('werewolf.secure=', 'werewolf.tpm=', 'werewolf.release=',
                            'werewolf.native=')) for word in words) or \
            'werewolf.disable=secureboot,tpm,ipe' not in words:
        raise ValueError('legacy image has an incompatible boot identity')
    return manifest


def build_one(images, target, snapshot, output):
    form, arch = target['form'], target['arch']
    profiles.identity(form, arch, 'legacy-boot')
    images.install_locks(snapshot)
    output.mkdir(parents=True)
    work = Path('build/legacy-images').resolve() / arch / form
    shutil.rmtree(work, ignore_errors=True)
    env = dict(os.environ, SOURCE_DATE_EPOCH='0', WEREWOLF_FORM_INPUTS=str(snapshot))
    # No code-signing or TPM credentials enter a compatibility build.
    for name in list(env):
        if name.startswith(('WEREWOLF_BOOT_', 'WEREWOLF_IPE_', 'WEREWOLF_PROTECTED_', 'WEREWOLF_TPM_')):
            env.pop(name)
    run(images.HOWL, '_build', '--with', form, '--arch', arch, '--build', work,
        '--disable=secureboot,tpm,ipe', 'image', 'slot', 'qcow2', env=env)
    root = work / form
    if (root / 'meta/usr/share/werewolf/dev').exists():
        raise ValueError('development images cannot be published')
    for name in ('stage0.zst', 'root.erofs', 'cmdline'):
        shutil.copyfile(root / 'slot' / name, output / name)
    for name in ('disk.qcow2', 'initramfs.zst'):
        shutil.copyfile(root / name, output / name)
    shutil.copyfile(work / 'vmlinuz', output / 'vmlinuz')
    raw = work / 'export.raw'
    run('qemu-img', 'convert', '-f', 'qcow2', '-O', 'raw', output / 'disk.qcow2', raw)
    run('zstd', '-q', '-T1', '-19', raw, '-o', output / 'disk.img.zst')
    images.archive_inputs(snapshot, output / 'inputs.tar.gz')
    write(output / 'packages.json', images.notes.inventory(snapshot, form, arch,
                                                         images.local_packages(snapshot, arch)))
    manifest = dict(format=FORMAT, **profiles.identity(form, arch, 'legacy-boot'),
                    disabled=['secureboot', 'tpm', 'ipe'], serial=target['serial'],
                    inputs=target['inputs'], commit=target['commit'],
                    raw_size=raw.stat().st_size,
                    files={name: catalog.record(output / name) for name in sorted(FILES)})
    validate(manifest, output)
    write(output / 'manifest.json', manifest)
    shutil.rmtree(work)


def build(images, snapshot, output):
    snapshot, output = Path(snapshot).resolve(), Path(output).resolve()
    plan = json.loads((snapshot / 'plan.json').read_text())
    images.native(plan['arch'])
    output.mkdir(parents=True)
    results = []
    for target in plan['targets']:
        if target['form'] not in profiles.FORMS:
            raise ValueError('unlisted form in legacy image plan')
        result = dict(target, status='build failed')
        results.append(result)
        try:
            # Legacy heads have their own publication history. A settled secure
            # target never implies that this profile has been built or tested.
            if target['status'] not in ('build', 'unchanged'):
                continue
            inputs = snapshot / target['form']
            chain = json.loads((inputs / 'input.json').read_text())['chain']
            if images.resolved_identity(target['form'], target['arch'], inputs, chain) != target['inputs'] or \
                    json.loads((inputs / 'tools.json').read_text()) != images.tool_versions(images.compiler(target['form'])):
                raise ValueError('legacy build inputs or tools changed after resolution')
            with (output / (target['form'] + '.log')).open('wb') as log, images.redirect(log):
                build_one(images, target, snapshot / target['form'], output / target['form'])
            result['status'] = 'built'
        except (OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
            print('legacy-boot: %s build failed: %s' % (target['form'], error), flush=True)
        finally:
            write(output / 'results.json', results)
    return any(result['status'] != 'built' for result in results)


def check(images, snapshot, first, second, output):
    snapshot, first, second, output = map(lambda path: Path(path).resolve(),
                                         (snapshot, first, second, output))
    plan = json.loads((snapshot / 'plan.json').read_text())
    images.native(plan['arch'])
    output.mkdir(parents=True)
    failed = False
    for target in plan['targets']:
        if target['form'] not in profiles.FORMS:
            raise ValueError('unlisted form in legacy image plan')
        form, arch = target['form'], target['arch']
        try:
            left, right = first / form, second / form
            manifest = validate(json.loads(catalog.read(left / 'manifest.json')), left)
            validate(json.loads(catalog.read(right / 'manifest.json')), right)
            if images.digests(left) != images.digests(right):
                raise ValueError('independent legacy boot builds differ')
            if any(manifest[key] != target[key] for key in ('form', 'arch', 'serial', 'commit', 'inputs')):
                raise ValueError('legacy build differs from resolved inputs')
            with tempfile.TemporaryDirectory(prefix='ww-legacy-disk-') as temporary:
                raw = Path(temporary) / 'disk.raw'
                images.exporter.unpack(left / 'disk.img.zst', raw, manifest['raw_size'])
                images.exporter.compare(raw, left / 'disk.qcow2', manifest['raw_size'])
            images.install_locks(snapshot / form)
            run('python3', 'test/form-coverage', '--form', form)
            run(images.HOWL, 'test', '--with', form, '--arch', arch,
                env=dict(os.environ, WEREWOLF_FORM_INPUTS=str(snapshot / form)))
            # The package updater and slot commitment are shared platform code.
            # Test their compatibility path as well as each exact image's boots.
            run('make', 'ARCH=' + arch, 'check-slot', 'check-updater')
            run('python3', 'test/check-legacy-image', left, output / (form + '-logs'))
            destination = output / form
            shutil.copytree(left, destination)
            write(destination / 'tests.json', dict(boot_profile='legacy-boot',
                manifest=catalog.sha(destination / 'manifest.json'),
                checks={name: True for name in sorted(CHECKS)}))
        except (OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
            print('legacy-boot: %s verification failed: %s' % (form, error), flush=True)
            failed = True
    return failed


def export(verified, output, provenance, targets, certificate='release/protected/image.crt'):
    """Sign only fully verified legacy artifacts; never produce a protected head."""
    output = Path(output).resolve()
    output.mkdir(parents=True, exist_ok=True)
    exported = []
    seen = set()
    for path in sorted(Path(verified).glob('**/manifest.json')):
        directory = path.parent
        manifest = validate(json.loads(catalog.read(path)), directory)
        identity = (manifest['form'], manifest['arch'])
        target = targets.get(identity)
        if identity in seen or target is None or target['status'] not in ('build', 'unchanged') or \
                manifest['commit'] != os.environ['GITHUB_SHA'] or \
                any(manifest[key] != target[key] for key in ('serial', 'commit', 'inputs')):
            raise ValueError('legacy artifact differs from this workflow\'s resolved target')
        seen.add(identity)
        report = json.loads(catalog.read(directory / 'tests.json', 64 << 10))
        if report != dict(boot_profile='legacy-boot', manifest=catalog.sha(path),
                          checks={name: True for name in sorted(CHECKS)}) or \
                any(value is not True for value in report['checks'].values()):
            raise ValueError('legacy artifact has incomplete or foreign tests')
        prefix = profiles.prefix(manifest['form'], manifest['arch'], 'legacy-boot')
        assets = output / prefix
        assets.mkdir()
        files = {}
        for name in sorted(FILES | {'tests.json'}):
            asset = prefix + ('.qcow2' if name == 'disk.qcow2' else '-' + name)
            shutil.copyfile(directory / name, assets / asset)
            files[name] = dict(asset=asset, **catalog.record(assets / asset))
        signed = dict(manifest, files=files, tests=report, provenance=provenance)
        head = assets / (prefix + '-downloads.json')
        write(head, signed)
        (assets / (head.name + '.sig')).write_bytes(catalog.sign(head.read_bytes(),
            os.environ['WEREWOLF_PROTECTED_IMAGE_KEY']))
        verify(assets, certificate)
        exported.append(dict(form=manifest['form'], arch=manifest['arch'], boot_profile='legacy-boot',
                             serial=manifest['serial'], assets=str(assets)))
    return exported


def verify(assets, certificate='release/protected/image.crt'):
    assets = Path(assets)
    heads = list(assets.glob('*-legacy-boot-downloads.json'))
    if len(heads) != 1:
        raise ValueError('missing or ambiguous legacy downloads manifest')
    head = heads[0]
    catalog.verify_signature(catalog.read(head), catalog.read(Path(str(head) + '.sig'), 512), certificate)
    manifest = json.loads(catalog.read(head))
    prefix = profiles.prefix(manifest['form'], manifest['arch'], manifest['boot_profile'])
    if manifest['format'] != FORMAT or manifest['boot_profile'] != 'legacy-boot' or \
            manifest['disabled'] != ['secureboot', 'tpm', 'ipe'] or \
            set(manifest['files']) != FILES | {'tests.json'}:
        raise ValueError('invalid signed legacy profile')
    expected = {head.name, head.name + '.sig'}
    for name, record in manifest['files'].items():
        asset = prefix + ('.qcow2' if name == 'disk.qcow2' else '-' + name)
        if record != dict(asset=asset, **catalog.record(assets / asset)):
            raise ValueError('legacy download differs from signed bytes')
        expected.add(asset)
    if {path.name for path in assets.iterdir()} != expected:
        raise ValueError('unexpected legacy release assets')
    report = manifest['tests']
    report_asset = assets / manifest['files']['tests.json']['asset']
    if json.loads(catalog.read(report_asset, 64 << 10)) != report or \
            report['checks'] != {name: True for name in sorted(CHECKS)} or \
            any(value is not True for value in report['checks'].values()):
        raise ValueError('legacy release tests are incomplete')
    candidate = {key: value for key, value in manifest.items() if key not in ('tests', 'provenance')}
    candidate['files'] = {name: {key: record[key] for key in ('sha256', 'size')}
                          for name, record in manifest['files'].items() if name != 'tests.json'}
    if report['boot_profile'] != 'legacy-boot' or \
            report['manifest'] != hashlib.sha256(catalog.encode(candidate)).hexdigest():
        raise ValueError('legacy tests describe another candidate')
    return manifest


def publish(exported, store, certificate='release/protected/image.crt'):
    rows = {}
    with tempfile.TemporaryDirectory(prefix='ww-legacy-index-') as temporary:
        previous = Path(temporary) / 'index.json'
        if store.fetch('boot-profiles.json', previous):
            envelope = json.loads(catalog.read(previous, 4 << 20))
            catalog.verify_signature(envelope['manifest'].encode(), bytes.fromhex(envelope['signature']), certificate)
            signed = json.loads(envelope['manifest'])
            if signed['format'] != 'werewolf-boot-profiles/1':
                raise ValueError('invalid prior boot profile catalog')
            for row in signed['legacy_boot']:
                profiles.identity(row['form'], row['arch'], row['boot_profile'])
                rows[(row['form'], row['arch'])] = row
    for target in exported:
        directory = Path(target['assets'])
        manifest = verify(directory, certificate)
        namespace = 'legacy-boot/' + manifest['form'] + '/' + manifest['arch']
        descriptor = catalog.sha(next(directory.glob('*-downloads.json')))
        receipt_key = namespace + '/latest/accepted.json'
        with tempfile.TemporaryDirectory(prefix='ww-legacy-floor-') as temporary:
            receipt = Path(temporary) / 'accepted.json'
            if store.fetch(receipt_key, receipt):
                previous = json.loads(catalog.read(receipt, 4 << 20))
                catalog.verify_signature(previous['manifest'].encode(), bytes.fromhex(previous['signature']), certificate)
                old = json.loads(previous['manifest'])
                if (old['form'], old['arch'], old['boot_profile']) != \
                        (manifest['form'], manifest['arch'], 'legacy-boot') or \
                        old['serial'] > manifest['serial'] or \
                        (old['serial'] == manifest['serial'] and previous['manifest'].encode() !=
                         next(directory.glob('*-downloads.json')).read_bytes()):
                    raise ValueError('legacy release would lower or reuse its signed release floor')
        for path in directory.iterdir():
            key = namespace + '/objects/' + descriptor + '/' + path.name
            with tempfile.TemporaryDirectory(prefix='ww-legacy-object-') as temporary:
                existing = Path(temporary) / 'object'
                if store.fetch(key, existing):
                    if catalog.record(existing) != catalog.record(path):
                        raise ValueError('immutable legacy object collision')
                else:
                    store.upload(key, path, True)
                if not store.fetch(key, existing) or catalog.record(existing) != catalog.record(path):
                    raise ValueError('public legacy object differs from GitHub asset')
                if store.bucket.startswith('s3://'):
                    downloader = importlib.machinery.SourceFileLoader('legacy_public_download', 'tools/boot-download').load_module()
                    downloader.fetch(catalog.PUBLIC + '/' + key, existing, path.stat().st_size,
                                     catalog.record(path))
        head = directory / (profiles.prefix(manifest['form'], manifest['arch'], 'legacy-boot') + '-downloads.json')
        with tempfile.TemporaryDirectory(prefix='ww-legacy-receipt-') as temporary:
            receipt = Path(temporary) / 'accepted.json'
            write(receipt, dict(manifest=head.read_text(), signature=Path(str(head) + '.sig').read_bytes().hex()))
            store.upload(receipt_key, receipt, False)
        for path in (Path(str(head) + '.sig'), head):
            store.upload(namespace + '/latest/' + path.name, path, False)
        rows[(manifest['form'], manifest['arch'])] = dict(form=manifest['form'], arch=manifest['arch'], boot_profile='legacy-boot',
                         serial=manifest['serial'], object=namespace + '/objects/' + descriptor,
                         files=manifest['files'])
    return [row for _, row in sorted(rows.items())]
