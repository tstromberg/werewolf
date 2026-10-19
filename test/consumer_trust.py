"""Keep public TLS roots when adding a private image-test mirror."""
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
