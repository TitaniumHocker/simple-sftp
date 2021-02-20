"""Base class of the package"""
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
from .util import (
    FileAttributes,
    find_knownhosts,
    make_socket,
    make_ssh_session,
    parse_attrs,
    pick_auth_method,
)

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
    :param knownhosts_autoadd: If set to `True` new host will be autoadded to current
        known_hosts file, otherwise - won't be added.
    :param force_keepalive: If set to `True` keepalive options for socket and SSH
        session will be forced.

    """
    def __init__(
        self,
        host: str,
        *,
        port: int = 22,
        username: t.Optional[str] = None,
        password: t.Optional[str] = None,
        pkey: t.Optional[str] = None,
        passphrase: str = '',
        agent_username: t.Optional[str] = None,
        knownhosts: t.Optional[str] = None,
        validate_host: bool = True,
        knownhosts_autoadd: bool = True,
        force_keepalive: bool = False,
    ):
        self.host: str = host
        self.port: int = port
        self.knownhosts: str = knownhosts if knownhosts is not None else find_knownhosts()
        self.validate_host: bool = validate_host
        self.knownhosts_autoadd: bool = knownhosts_autoadd
        self.force_keepalive: bool = force_keepalive
        self.auth_handler: AuthHandlersType = pick_auth_method(
            username, password, agent_username, pkey, passphrase
        )
        self._session: SFTP
        self._host_validated: bool = False

    def process_host_validation(self):
        """Validate host"""
        pass

    def connect(self) -> SFTP:
        """Start new SFTP session

        :return: SFTP session.
        """
        if self.validate_host and not self._host_validated:
            self.process_host_validation()
        ssh_session = make_ssh_session(
            make_socket(self.host, self.port, force_keepalive=self.force_keepalive),
            use_keepalive=self.force_keepalive
        )
        self.auth_handler.auth(ssh_session)
        self._session = ssh_session.sftp_init()

    def disconnect(self):
        """Disconnect current session"""
        if hasattr(self, '_session') and isinstance(self._session, SFTP):
            self._session.session.disconnect()
            del self._session

    @property
    def session(self) -> SFTP:
        """Current SFTP session"""  # noqa: D401
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

    def realpath(self, path):
        """Get real path for path

        :param path: Path to get real path for.
        :return: Real path.
        """
        return self.session.realpath(path)

    def ls(self, path: str = '.') -> t.List[t.Tuple[str, FileAttributes]]:
        """Get list of files and directories

        :param path: Path to be listed.
        :return: List of tuples with file/dir names and attributes.
        """
        with self.session.opendir(path) as dh:
            return [
                (name.decode('utf-8'), parse_attrs(attrs))
                for _, name, attrs in dh.readdir()
            ]

    def mv(self, sorce: str, dest: str):
        """Move/rename file

        :param source: Source path.
        :param dest: Destination path.
        """
        pass

    def rm(self, path: str):
        """Remove file

        :param path: Path of file to delete.
        """
        self.session.unlink(path)

    def rmdir(self, path: str):
        """Remove directory

        :param path: Path to directory to remove.
        """
        self.session.rmdir(path)

    def mkdir(self, path: str, permissions: str = 'rwxrwxr-x'):
        """Create directory

        :param path: Path of directory to create.
        :param permissions: Unix-like string with permissions of new directory.
        """
        pass

    def get_stat(self, path: str):
        """Get stat"""
        pass

    def set_stat(self, path: str):
        """Set stat"""
        pass

    def ln(self, path: str, target: str):
        """Create symlink

        :param path: Source path.
        :param target: Target path.
        """
        return self.session.symlink(path, target)

    def unlink(self, path: str):
        """Delete symlink

        :param path: Path to symlink to delete.
        """
        pass

    def get(self, path: str, fh: t.IO):
        """Get file

        :param path: File path to download.
        :param fh: File object to download into.
        """
        pass

    def put(self, fh: t.IO, path: str):
        """Put file

        :param fh: File object for upload.
        :param path: Remote path to upload.
        """
        pass
