import os
import socket
import subprocess
import time
import typing as t


class Server:
    """OpenSSH server(sshd) wrapper

    This class is simple wrapper for OpenSSH server(sshd) for testing purposes.

    :param host: Hostname to run sshd.
    :param port: Port to run sshd.
    :param authorized_keys: Tuple of authorized keys public keys in OpenSSH format.
    :param hostkeys: Tuple of server hostkeys.
    :param allowed_auth_methods: Mask of allowed auth methods.
    """

    def __init__(
        self,
        host: str = "127.0.0.1",
        port: t.Optional[int] = None,
        authorized_keys: t.Tuple[bytes, ...] = (),
        hostkey: t.Optional[bytes] = None,
    ):
        pass

    def start(self):
        pass

    def stop(self):
        pass

    def restart(self):
        self.stop()
        self.start()

    def reload(self):
        pass
