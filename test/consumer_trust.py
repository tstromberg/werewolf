"""Trust and boot evidence for source-free image consumers."""
import os
from pathlib import Path
import ssl


SYSTEM_BUNDLES = (
    '/etc/ssl/certs/ca-certificates.crt',
    '/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem',
    '/etc/ssl/cert.pem',
    '/opt/homebrew/etc/ca-certificates/cert.pem',
    '/usr/local/etc/ca-certificates/cert.pem',
)


def mirror_roots(certificate):
    context = ssl.create_default_context()
    # Fedora's Python can report no cafile and an empty hashed CA directory,
    # although the extracted system bundle exists and curl normally uses it.
    for filename in (os.environ.get('CURL_CA_BUNDLE'), *SYSTEM_BUNDLES):
        if filename and Path(filename).is_file():
            context.load_verify_locations(cafile=filename)
    public = context.get_ca_certs(binary_form=True)
    if not public:
        raise RuntimeError('public TLS roots are missing; install ca-certificates')
    pem = ''.join(ssl.DER_cert_to_PEM_cert(cert) for cert in public).encode()
    return pem + Path(certificate).read_bytes()


UPDATE_GATES = {'ab_upgrade', 'operator_rollback', 'unhealthy_fallback', 'retirement_cuts'}
CANDIDATE_GATES = {'secure_boot', 'ipe', 'verified_root', 'rollback_protected',
                   'tamper_refused', 'no_consumer_builds', 'no_vendor_private_keys', 'fresh_download'}
PUBLISHED_CHECKS = ('boot-secure-boot', 'boot-ipe-enforced', 'boot-rollback-protected',
                    'files-root-verity', 'files-root-readonly', 'files-exec-refused', 'files-system-writes')
SSH_CHECKS = PUBLISHED_CHECKS[:4]


def validate_updates(evidence, provider, arch, commit):
    """Require this tree's complete update proof on the same runtime target."""
    if evidence.get('format') != 'werewolf-update-evidence/1' or evidence.get('passed') is not True:
        raise ValueError('the update evidence records no pass')
    if (evidence.get('provider'), evidence.get('arch'), evidence.get('commit')) != (provider, arch, commit):
        raise ValueError('the update evidence is of another target or source revision')
    checks = evidence.get('checks', {})
    if not isinstance(checks, dict) or any(checks.get(name) is not True for name in UPDATE_GATES):
        raise ValueError('the update lifecycle gates are incomplete')


def candidate_boot(value, required, channel, index):
    """Admit only a committed boot of the exact signed channel and release index."""
    if value.get('ready') is not True or value.get('committed') is not True:
        return None
    words = value.get('cmdline', '').split()
    for key, expected in (('werewolf.channel=', channel), ('werewolf.index=', str(index))):
        if [word for word in words if word.startswith(key)] != [key + expected]:
            raise ValueError('the running boot is not the candidate')
    entries = value.get('checks', [])
    checks = {entry['id']: entry['result'] for entry in entries}
    if len(checks) != len(entries) or any(checks.get(name) != 'pass' for name in required):
        raise ValueError('guest protection or native tamper probe missing')
    boot_id = value.get('boot_id')
    if not isinstance(boot_id, str) or not boot_id:
        raise ValueError('committed boot has no boot identity')
    return dict(boot_id=boot_id, checks=checks)
