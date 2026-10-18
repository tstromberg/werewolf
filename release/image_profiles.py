"""The public image set and explicit boot profiles of the shared release flow."""
from pathlib import Path
import re

BASE_FORMS = ('minimal', 'prod', 'prod-ssh', 'playground')
FORMS = tuple(sorted(path.parent.name for path in
                     Path(__file__).resolve().parent.parent.joinpath('forms').glob('*/form.yaml')
                     if re.fullmatch(r'[a-z][a-z0-9-]{0,63}', path.parent.name)))
PROFILES = ('secure-boot', 'legacy-boot')
ARCHES = ('aarch64', 'x86_64')


def identity(form, arch, profile):
    if form not in FORMS or arch not in ARCHES or profile not in PROFILES:
        raise ValueError('unsupported published image identity')
    return dict(form=form, arch=arch, boot_profile=profile)


def prefix(form, arch, profile):
    identity(form, arch, profile)
    return '-'.join((form, arch, profile))
