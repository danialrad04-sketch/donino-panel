import fcntl
import os
import ssl
from pathlib import Path

from .common import InstallError, atomic_write, run


def validate_certificate(domain, certificate, key, *, ca_file=None, min_validity=300):
    certificate, key = Path(certificate), Path(key)
    if not certificate.is_file() or not key.is_file():
        raise InstallError("Certificate and private key files are required", 5)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    try:
        context.load_cert_chain(certificate, key)
    except (OSError, ssl.SSLError) as exc:
        raise InstallError("Invalid or mismatched certificate/private key", 5) from exc
    run(
        [
            "openssl",
            "x509",
            "-in",
            str(certificate),
            "-noout",
            "-checkend",
            str(min_validity),
        ],
        capture=True,
        code=5,
    )
    verify = [
        "openssl",
        "verify",
        "-verify_hostname",
        domain,
        "-untrusted",
        str(certificate),
    ]
    if ca_file:
        verify += ["-CAfile", str(ca_file)]
    verify += [str(certificate)]
    run(verify, capture=True, code=5)


def install_certificate(
    domain, certificate, key, directory, *, ca_file=None, check=None, reload=None
):
    """Validate before mutation; roll back the matching pair on config/reload error."""
    validate_certificate(domain, certificate, key, ca_file=ca_file)
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    with open(directory / ".lock", "a") as lock:
        os.chmod(directory / ".lock", 0o600)
        fcntl.flock(lock, fcntl.LOCK_EX)
        cert, private = directory / "panel.crt", directory / "panel.key"
        previous = [
            (path, path.read_bytes() if path.exists() else None)
            for path in (cert, private)
        ]
        try:
            atomic_write(cert, Path(certificate).read_bytes())
            atomic_write(private, Path(key).read_bytes())
            if check:
                check()
            if reload:
                reload()
        except BaseException:
            for path, data in previous:
                if data is None:
                    path.unlink(missing_ok=True)
                else:
                    atomic_write(path, data)
            raise
