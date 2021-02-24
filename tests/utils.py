import typing as t

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import dsa, ec, rsa


class KeyPair(t.NamedTuple):
    private: bytes
    public: bytes


def make_keypair(type: str, passphrase: t.Optional[str] = None) -> KeyPair:
    """Generate RSA/DSA/ECDSA keypair

    :param type: Type of keypair encryption, can be `rsa`, `dsa` or `ecdsa`.
    :param passphrase: Passphrase to set for private key.
    :return: Tuple with keypair as bytes, public key in OpenSSH format.
        First element of tuple is private key and second is public key.
    """
    keymakers: t.Dict[str, t.Callable] = {
        "rsa": lambda: rsa.generate_private_key(
            backend=default_backend(), public_exponent=65537, key_size=2048
        ),
        "dsa": lambda: dsa.generate_private_key(1024, backend=default_backend()),
        "ecdsa": lambda: ec.generate_private_key(
            ec.SECP256R1(), backend=default_backend()
        ),
    }
    try:
        key = keymakers[type]()
    except KeyError:
        raise TypeError(
            "Invalid encryption type for keypair, available types: {}".format(
                ", ".join(keymakers.keys())
            )
        )
    if passphrase:
        encryption: t.Any = serialization.BestAvailableEncryption(passphrase.encode())
    else:
        encryption = serialization.NoEncryption()
    return KeyPair(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            encryption,
        ),
        key.public_key().public_bytes(
            serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH
        ),
    )
