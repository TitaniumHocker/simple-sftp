import logging
import typing as t

import ssh2
from ssh2.knownhost import (LIBSSH2_KNOWNHOST_KEY_SSHRSA,
                            LIBSSH2_KNOWNHOST_KEYENC_RAW,
                            LIBSSH2_KNOWNHOST_TYPE_PLAIN)
from ssh2.session import (LIBSSH2_HOSTKEY_HASH_SHA1, LIBSSH2_HOSTKEY_TYPE_RSA,
                          Session)
from ssh2.sftp import SFTP

from .auth import AgentAuthorization, KeyAuthorization, PasswordAuthorization
from .util import find_knownhosts, make_socket, make_ssh_session

logger = logging.getLogger(__name__)


class SFTPClient:
    """Simple SFTP client

    :param host: Host name to connect.
    :param port: Port to connect.
    :param username: Username that will be used for
        username/password authorization, optional.
    :param password: Password that will be used for
        username/password authorization, optional.
    :param pkey: Private key path that will be used
        for key authorization, optional.
    :param agent_auth_user: Username for user agent
        authorization method, optional.
    :param knownhosts_path: Path to known_hosts file,
        if not provided an attempt will be made  to
        find the file in common places.
    :param force_keepalive: If set to `True` keepalive
        options for socket and ssh session will be forced.
    :param knownhosts_behavior: Type of behavior for
        processing known_hosts file, optional."""
    def __init__(
        self,
        host: str,
        port: int = 22,
        username: t.Optional[str] = None,
        password: t.Optional[str] = None,
        pkey: t.Optional[str] = None,
        agent_auth_user: t.Optional[str] = None,
        host_validation: bool = True,
        force_keepalive: bool = False,
        knownhosts_auto: bool = True,
        knownhosts_path: t.Optional[str] = None
    ):
        self.host: str = host
        self.port: int = port
        self.host_validation: bool = host_validation
        self.force_keepalive: bool = force_keepalive
        self.knownhosts_path: str = knownhosts_path \
            if knownhosts_path is not None else find_knownhosts()
        self._session: SFTP

    @property
    def session(self) -> SFTP:
        if hasattr(self, '_session') and isinstance(self._session, SFTP):
            return self.session
        pass

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        pass

    @property
    def hostkey_hash(self) -> str:
        """SHA1 digest of remote host key"""
        return self.session.session.hostkey_hash(
            LIBSSH2_HOSTKEY_HASH_SHA1
        ).decode('utf-8')

    def validate_host(self):
        pass

    def ls(self, path: str = '.'):
        pass

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
