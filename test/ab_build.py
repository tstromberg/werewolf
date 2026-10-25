"""Build private A/B fixtures without the public managed-bundle export flow."""
from pathlib import Path
import shutil


def arguments(howl, form, arch, kernel, key, cert, build, channel, serial,
              boot_key=None, boot_cert=None, tpm=False, *, app=None,
              goals=('prebuilt', 'qcow2'), disk_args=None, index=1):
    form, build = Path(form), Path(build)
    args = [str(howl), '_build', '--with', str(form), '--arch', arch,
            '--build', str(build), '--ipe-kernel', str(kernel), '--ipe-key', str(key),
            '--ipe-cert', str(cert), '--ipe-updates', channel, '--image-serial', serial,
            '--image-index', str(index)]
    disabled = []
    if boot_key:
        if not boot_cert:
            raise ValueError('a test boot key needs its certificate')
        args += ['--boot-key', str(boot_key), '--boot-cert', str(boot_cert), '--boot-native']
    else:
        disabled.append('secureboot')
    if tpm:
        args += ['--tpm']
    else:
        disabled.append('tpm')
    if disabled:
        args += ['--disable=' + ','.join(disabled)]
    if app:
        args += ['--app-root', str(app)]
    if disk_args:
        args += ['--disk-args', disk_args]
    return args + list(goals), build / (form.name + ('-app' if app else '') + '-ipe')


def export(output, form, arch, destination):
    """Keep only the public artifacts the provider adapters consume."""
    destination = Path(destination)
    destination.mkdir(parents=True, exist_ok=True)
    prefix = Path(form).name + '-' + arch + '-'
    for name in ['vmlinuz', 'stage0.zst', 'root.erofs', 'cmdline']:
        shutil.copyfile(output / 'slot' / name, destination / (prefix + name))
    shutil.copyfile(output / 'disk.qcow2', destination / (prefix + 'disk.qcow2'))
    uki = output / 'slot/uki.efi'
    if uki.is_file():
        shutil.copyfile(uki, destination / (prefix + 'uki'))
