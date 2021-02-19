import logging
import typing as t

import ssh2
from ssh2.knownhost import (
    LIBSSH2_KNOWNHOST_KEY_SSHRSA,
    LIBSSH2_KNOWNHOST_KEYENC_RAW,
    LIBSSH2_KNOWNHOST_TYPE_PLAIN,
)
from ssh2.session import LIBSSH2_HOSTKEY_HASH_SHA1, LIBSSH2_HOSTKEY_TYPE_RSA, Session
from ssh2.sftp import SFTP

from .auth import AuthHandlersType
from .util import find_knownhosts, make_socket, make_ssh_session, parse_attrs, pick_auth_method

logger = logging.getLogger(__name__)


class SFTPClient:
    """
    Simple SFTP client

    :param host: Host name to connect.
    :param port: Port to connect.
    :param username: Username that will be used for username/password authorization.
    :param password: Password that will be used for username/password authorization.
    :param pkey: Private key path that will be used for key authorization.
    :param passphrase: Passphrase to unlock private key.
    :param agent_username: Username for user agent authorization method.
    :param knownhosts: Path to *known_hosts* file. If not provided an attempt will
        be made to find the file in common places.
    :param validate_host: If set to `True` host validation will be made.
    :param force_keepalive: If set to `True` keepalive options for socket and SSH
        session will be forced.
    """
    def __init__(
        self,
        host: str,
        port: int = 22,
        username: t.Optional[str] = None,
        password: t.Optional[str] = None,
        pkey: t.Optional[str] = None,
        passphrase: str = '',
        agent_username: t.Optional[str] = None,
        knownhosts: t.Optional[str] = None,
        validate_host: bool = True,
        force_keepalive: bool = False,
    ):
        self.host: str = host
        self.port: int = port
        self.knownhosts: str = knownhosts if knownhosts is not None else find_knownhosts()
        self.validate_host: bool = validate_host
        self.force_keepalive: bool = force_keepalive
        self.auth_handler: AuthHandlersType = pick_auth_method(
            username, password, agent_username, pkey, passphrase
        )
        self._session: SFTP

    def connect(self) -> SFTP:
        """
        Start new SFTP session

        :return: SFTP session.
        """
        ssh_session = make_ssh_session(
            make_socket(self.host, self.port, force_keepalive=self.force_keepalive),
            use_keepalive=self.force_keepalive
        )
        self.auth_handler.auth(ssh_session)
        self._session = ssh_session.sftp_init()

    def disconnect(self):
        if hasattr(self, '_session') and isinstance(self._session, SFTP):
            self._session.session.disconnect()
            del self._session

    @property
    def session(self) -> SFTP:
        if hasattr(self, '_session') and isinstance(self._session, SFTP):
            return self._session
        self.connect()
        return self._session

    def __enter__(self):
        self.connect()
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.disconnect()

    @property
    def hostkey_hash(self) -> str:
        """SHA1 digest of remote host key"""
        return self.session.session.hostkey_hash(
            LIBSSH2_HOSTKEY_HASH_SHA1
        ).decode('utf-8')

    def ls(self, path: str = '.') -> t.List[t.Tuple[str, t.Any]]:
        """Get list of files and directories

        :param path: Path to be listed.
        :return: List of tuples with file/dir names and attributes."""
        with self.session.opendir(path) as dh:
            return [
                (name.decode('utf-8'), parse_attrs(attrs))
                for _, name, attrs in dh.readdir()
            ]

    def mv(self, from_path: str, to_path: str):
        pass

    def rm(self, path: str):
        pass

    def rmdir(self, path: str):
        pass

    def mkdir(self, path: str):
        pass

    def get_stat(self, path: str):
        pass

    def set_stat(self, path: str):
        pass

    def ln(self, from_path: str, to_path: str):
        pass

    def unlink(self, path: str):
        pass

    def get(self, path: str, fh: t.IO):
        pass

    def put(self, fh: t.IO, path: str):
        pass
