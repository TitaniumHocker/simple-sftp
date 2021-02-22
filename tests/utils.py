import typing as t

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import dsa, ec, rsa


def make_rsa_keypair(passphrase: t.Optional[str] = None) -> t.Tuple[bytes, bytes]:
    """Generate RSA keypair

    :param passphrase: Passphrase to set for private key.
    :return: Tuple with RSA keypair as bytes, public key in OpenSSH format.
        First element of tuple is private key and second is public key.
    """
    key = rsa.generate_private_key(
        backend=default_backend(), public_exponent=65537, key_size=2048
    )
    if passphrase:
        encryption: t.Any = serialization.BestAvailableEncryption(passphrase.encode())
    else:
        encryption = serialization.NoEncryption()
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        encryption,
    ), key.public_key().public_bytes(
        serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH
    )


def make_dsa_keypair(passphrase: t.Optional[str] = None) -> t.Tuple[bytes, bytes]:
    """Generate DSA keypair

    :param passphrase: Passphrase to set for private key.
    :return: Tuple with DSA keypair as bytes, public key in OpenSSH format.
        First element of tuple is private key and second is public key.
    """
    key = dsa.generate_private_key(1024, backend=default_backend)
    if passphrase:
        encryption: t.Any = serialization.BestAvailableEncryption(passphrase.encode())
    else:
        encryption = serialization.NoEncryption()
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        encryption,
    ), key.public_key().public_bytes(
        serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH
    )


def make_ecdsa_keypair(passphrase: t.Optional[str] = None) -> t.Tuple[bytes, bytes]:
    """Generate ECDSA keypair

    :param passphrase: Passphrase to set for private key.
    :return: Tuple with ECDSA keypair as bytes, public key in OpenSSH format.
        First element of tuple is private key and second is public key.
    """
    key = ec.generate_private_key(ec.SECP256R1(), backend=default_backend())
    if passphrase:
        encryption: t.Any = serialization.BestAvailableEncryption(passphrase.encode())
    else:
        encryption = serialization.NoEncryption()
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        encryption,
    ), key.public_key().public_bytes(
        serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH
    )
