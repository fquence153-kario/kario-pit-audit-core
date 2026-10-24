"""EPHEMERAL, synthetic TSA issuer; never use in production.

Generates short-lived self-signed CA / TSA private keys inside caller's temp
folder. NEVER copy this folder or its keys into an open-source repository.
"""
from pathlib import Path
import subprocess

POLICY_OID = '1.3.6.1.4.1.55555.3161.1'


def _run(executable, args):
    proc = subprocess.run([executable, *args], capture_output=True, text=True, timeout=30)
    if proc.returncode:
        raise RuntimeError('Synthetic OpenSSL fixture generation failed: ' + proc.stderr[-400:])


def make_fixture(directory, *, openssl_executable, commitment: bytes, accuracy_seconds=1):
    root = Path(directory)
    root.mkdir(parents=True, exist_ok=True)
    (_content := root / 'commitment.bin').write_bytes(commitment)
    ca_key = root / 'ca.key'
    ca = root / 'ca.crt'
    tsa_key = root / 'tsa.key'
    csr = root / 'tsa.csr'
    tsa = root / 'tsa.crt'
    ext = root / 'tsa.ext'
    req = root / 'request.tsq'
    token = root / 'token.tsr'
    conf = root / 'tsa.cnf'
    serial = root / 'tsa.srl'
    _run(openssl_executable, ['req', '-x509', '-newkey', 'rsa:3072', '-nodes',
                               '-keyout', str(ca_key), '-out', str(ca), '-days', '2',
                               '-subj', '/CN=KARIO Synthetic CA v04c',
                               '-addext', 'basicConstraints=critical,CA:TRUE',
                               '-addext', 'keyUsage=critical,keyCertSign,cRLSign'])
    _run(openssl_executable, ['req', '-newkey', 'rsa:3072', '-nodes',
                               '-keyout', str(tsa_key), '-out', str(csr),
                               '-subj', '/CN=KARIO Synthetic TSA v04c'])
    ext.write_text('\n'.join([
        'basicConstraints=critical,CA:FALSE',
        'keyUsage=critical,digitalSignature',
        'extendedKeyUsage=critical,timeStamping',
        'subjectKeyIdentifier=hash',
        'authorityKeyIdentifier=keyid,issuer',
        '']), encoding='ascii')
    _run(openssl_executable, ['x509', '-req', '-in', str(csr), '-CA', str(ca),
                               '-CAkey', str(ca_key), '-CAcreateserial',
                               '-out', str(tsa), '-days', '2', '-extfile', str(ext)])
    serial.write_text('01\n', encoding='ascii')
    conf.write_text('\n'.join([
        '[tsa]', 'default_tsa=lab', '[lab]', f'serial={serial.as_posix()}',
        'crypto_device=builtin', f'signer_cert={tsa.as_posix()}', f'certs={ca.as_posix()}',
        f'signer_key={tsa_key.as_posix()}', 'signer_digest=sha256',
        f'default_policy={POLICY_OID}', 'ess_cert_id_alg=sha256',
        'digests=sha256', f'accuracy=secs:{accuracy_seconds}',
        'ordering=yes', 'tsa_name=yes', 'ess_cert_id_chain=no',
    ]) + '\n', encoding='utf-8')
    _run(openssl_executable, ['ts', '-query', '-data', str(_content), '-sha256',
                               '-cert', '-out', str(req)])
    _run(openssl_executable, ['ts', '-reply', '-config', str(conf),
                               '-queryfile', str(req), '-token_out',
                               '-out', str(token)])
    return {'token': token, 'request': req, 'ca': ca, 'tsa': tsa}
