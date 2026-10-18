"""The public image set and explicit boot profiles of the shared release flow."""
FORMS = ('minimal', 'prod-ssh', 'playground')
# Keep existing dispatch scopes compatible; both select the same public set.
BASE_FORMS = FORMS
PROFILES = ('secure-boot', 'legacy-boot')
ARCHES = ('aarch64', 'x86_64')


def identity(form, arch, profile):
    if form not in FORMS or arch not in ARCHES or profile not in PROFILES:
        raise ValueError('unsupported published image identity')
    return dict(form=form, arch=arch, boot_profile=profile)


def prefix(form, arch, profile):
    identity(form, arch, profile)
    return '-'.join((form, arch, profile))
