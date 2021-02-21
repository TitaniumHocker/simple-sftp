"""Base class of the package"""
import logging
import os
import typing as t
from functools import lru_cache
from hashlib import sha1

import ssh2

from . import auth, excs, util

logger = logging.getLogger(__name__)


class SFTP:
    """
    SFTP client

    .. note::
        All arguments except `host` are keyword-only arguments.

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
        known_hosts file, otherwise - won't be added and exception would be raised
        on host verification.
    :param session_keepalive: If set to `True` SSH session keepalive configuration will be used.
    :param force_socket_keepalive: If set to `True` keepalive options for socket will be forced.
    :param reconnect_on_drop: If set to `True` client will try to reconnect if
        connection was dropped by remote host.
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
        session_keepalive: bool = False,
        force_socket_keepalive: bool = False,
        reconnect_on_drop: bool = True
    ):
        self.host: str = host
        self.port: int = port
        self.validate_host: bool = validate_host
        self.knownhosts: str = knownhosts if knownhosts is not None else util.find_knownhosts()
        self.knownhosts_autoadd: bool = knownhosts_autoadd

        self.session_keepalive: bool = session_keepalive
        self.force_socket_keepalive: bool = force_socket_keepalive
        self.reconnect_on_drop: bool = reconnect_on_drop

        self.auth_handler: auth.AuthHandlersType = util.pick_auth_method(
            username, password, agent_username, pkey, passphrase
        )

        self._session: ssh2.sftp.SFTP
        self._home: str
        self._host_validated: bool = False
        self._cwd: str = '.'
        self._uid: t.Optional[int] = None
        self._gid: t.Optional[int] = None

    @property
    def cwd(self) -> str:
        """Current working directory"""  # noqa: D401
        return self._cwd

    @property
    def home(self) -> str:
        """Home directory"""  # noqa: D401
        return self._home

    def _preprocess_path(self, path: str) -> str:
        """Preprocess path

        Translates relative path to cwd/home relative path.

        :param path: Source path.
        :return: Translated path.
        """
        if path.startswith('/'):
            return path
        if path.startswith('~/'):
            return os.path.join(self.home, path[2:])
        if path == '~' or path == '':
            return self.home
        return os.path.join(self.cwd, path)

    @lru_cache
    def _check_permissions(self, path: str, permissions: str):
        """Check requested permissions on path

        This function checks requested permissions on path and
        if check fails than it raises corresponding exception.

        :raise TypeError: If invalid permissions string was provided.
        :raise NotFoundError: If requested path not found.
        :raise PermissionDeniedError: If not enough permissions to access
            requested file or directory.
        """
        if not util.RWX_PATTERN.match(permissions):
            raise TypeError(f"Unexpected permissions string {permissions}")

        try:
            attrs = util.parse_attrs(self.session.stat(path))
        except ssh2.exceptions.SFTPProtocolError:
            return excs.NotFoundError(f"Cannot access {path}: no such file or directory")

        if self._uid is None or self._gid is None:
            return None

        if len(attrs.permissions) == 10:
            usr_perm = attrs.permissions[1:4]
            grp_perm = attrs.permissions[4:7]
            oth_perm = attrs.permissions[7:]
        else:
            usr_perm = attrs.permissions[0:3]
            grp_perm = attrs.permissions[3:6]
            oth_perm = attrs.permissions[6:]

        for perm in permissions:
            if not any([
                attrs.uid == self._uid and perm in usr_perm,
                attrs.gid == self._gid and perm in grp_perm,
                perm in oth_perm
            ]):
                return excs.PermissionDeniedError(f"Cannot access {path}: permission denied")

        return None

    def cd(self, path: str = '~'):
        """Change directory

        Changes the current working directory.

        :param path: Directory to use, can be both relative and absolute.
        :raise ChangingDirectoryError: If directory not found or not enough
            permissions to change to this directory.
        """
        ppath = self._preprocess_path(path)

        try:
            attrs: util.FileAttributes = self.get_stat(ppath)
        except ssh2.exceptions.SFTPProtocolError as e:
            raise excs.ChangingDirectoryError(f"Directory {path} not found") from e

        if self._uid is None or self._gid is None:
            self._cwd = ppath
            return

        if len(attrs.permissions) == 10:
            usr_perm = attrs.permissions[1:4]
            grp_perm = attrs.permissions[4:7]
            oth_perm = attrs.permissions[7:]
        else:
            usr_perm = attrs.permissions[0:3]
            grp_perm = attrs.permissions[3:6]
            oth_perm = attrs.permissions[6:]

        if not any([
            attrs.uid == self._uid and 'r' in usr_perm and 'x' in usr_perm,
            attrs.gid == self._gid and 'r' in grp_perm and 'x' in grp_perm,
            'r' in oth_perm and 'x' in oth_perm
        ]):
            raise excs.ChangingDirectoryError("Permission denied")

        self._cwd = ppath

    def _process_host_validation(self, session: ssh2.session.Session):
        """Validate host

        :param session: SSH session.
        :raise HostValidationError: If host validation failed.
        """
        logger.info("Processing host validation...")
        knownhosts = session.knownhost_init()

        try:
            hosts_count = knownhosts.readfile(self.knownhosts)
            logger.info("Found %i hosts in hosts file %s", hosts_count, self.knownhosts)
        except ssh2.exceptions.KnownHostReadFileError:
            if self.knownhosts_autoadd:
                msg = ("Could't read knownhosts file in %s, file seems to be missing. "
                       "A new file will be created on this path when adding a host.")
            else:
                msg = "Could't read knownhosts file in path %s, file seems to be missing."
            logger.warning(msg, self.knownhosts)

        hostkey, keytype = session.hostkey()
        knownhost_typemask = util.pick_knownhost_typemask(keytype)

        try:
            knownhosts.checkp(self.host.encode('utf-8'), self.port, hostkey, knownhost_typemask)
            logger.info("Host validation passed.")
        except ssh2.exceptions.KnownHostCheckNotFoundError as e:
            if not self.knownhosts_autoadd:
                raise excs.HostValidationError(
                    f"Host {self.host} not found in knownhosts. "
                    f"Unknown hosts can be autoadded with knownhosts_autoadd=True kwarg."
                ) from e
            logger.info("Adding new host %s to knownhosts file.", self.host)
            knownhosts.addc(
                self.host.encode('utf-8'),
                hostkey, knownhost_typemask,
                comment="Added by simple-sftp python package.".encode('utf-8')
            )
            knownhosts.writefile(self.knownhosts)
            logger.info("Host %s was added to known_hosts file.", self.host)
        except ssh2.exceptions.KnownHostCheckMisMatchError as e:
            raise excs.HostValidationError(
                util.HOSTKEY_VERIFICATION_FAILED_MESSAGE.format(
                    host=self.host,
                    hostkey_hash=sha1(hostkey).hexdigest(),
                    expected_hostkey_hash=sha1([
                        knownhost.key for knownhost in knownhosts.get()
                        if knownhost.name.decode() == self.host
                    ][0]).hexdigest(),
                    knownhosts=self.knownhosts,
                    line_number=[
                        i + 1 for i, knownhost in enumerate(knownhosts.get())
                        if knownhost.name.decode() == self.host
                    ][0]
                )
            ) from e

        self._host_validated = True

    def connect(self) -> ssh2.sftp.SFTP:
        """Start new SFTP session

        :return: SFTP session.
        """
        ssh_session = util.make_ssh_session(
            util.make_socket(self.host, self.port, force_keepalive=self.force_socket_keepalive),
            use_keepalive=self.session_keepalive
        )
        if self.validate_host and not self._host_validated:
            self._process_host_validation(ssh_session)
        self.auth_handler.auth(ssh_session)
        self._session = ssh_session.sftp_init()

        self._home = self._session.realpath('.')

        if self._uid is None or self._gid is None:
            if util.HOMEDIR_PATTERN.match(self._session.realpath('.')):
                attrs = util.parse_attrs(self._session.stat('.'))
                self._uid = attrs.uid
                self._gid = attrs.gid

        self._check_permissions.cache_clear()

        return self._session

    def disconnect(self):
        """Disconnect current session"""
        if hasattr(self, '_session') and isinstance(self._session, ssh2.sftp.SFTP):
            self._session.session.disconnect()
            del self._session

    @property
    def session(self) -> ssh2.sftp.SFTP:
        """Current SFTP session"""  # noqa: D401
        if hasattr(self, '_session') and isinstance(self._session, ssh2.sftp.SFTP):
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
        hostkey, _ = self.session.session.hostkey()
        return sha1(hostkey).hexdigest()

    @util.reconnect
    def realpath(self, path) -> str:
        """Get real path for path

        :param path: Path to get real path for.
        :return: Real path.
        """
        try:
            return self.session.realpath(path)
        except ssh2.exceptions.SFTPProtocolError as e:
            raise excs.NotFoundError(f"File or directory {path} not found.") from e

    @util.reconnect
    def ls(self, path: str = '.') -> t.List[t.Tuple[str, util.FileAttributes]]:
        """Get list of files and directories

        :param path: Path to be listed.
        :return: List of tuples with file/dir names and attributes.
        """
        ppath = self._preprocess_path(path)
        with self.session.opendir(ppath) as dh:
            return [
                (name.decode('utf-8'), util.parse_attrs(attrs))
                for _, name, attrs in dh.readdir()
            ]

    @util.reconnect
    def mv(self, sorce: str, dest: str):
        """Move/rename file

        :param source: Source path.
        :param dest: Destination path.
        """
        pass

    @util.reconnect
    def rm(self, path: str):
        """Remove file

        :param path: Path of file to delete.
        """
        try:
            self.session.unlink(path)
        except ssh2.exceptions.SFTPProtocolError as e:
            raise excs.NotFoundError("File {path} not found.") from e

    @util.reconnect
    def rmdir(self, path: str):
        """Remove directory

        :param path: Path to directory to remove.
        :raise NotFoundError: If directory does not exists.
        :raise PermissionDeniedError: If not enough permissions to remove directory.
        """
        ppath = self._preprocess_path(path)
        try:
            attrs = util.parse_attrs(self.session.stat(ppath))
        except ssh2.exceptions.SFTPProtocolError as e:
            raise excs.NotFoundError(f"Directory {path} does not exists.") from e

        if attrs.type != 'd':
            raise excs.NotFoundError(f"Directory {path} does not exists.")

        self.session.rmdir(path)

    @util.reconnect
    def mkdir(self, path: str, permissions: str = 'rwxrwxr-x'):
        """Create directory

        :param path: Path of directory to create.
        :param permissions: Unix-like string with permissions of new directory.
        """
        pass

    @util.reconnect
    def get_stat(self, path: str) -> util.FileAttributes:
        """Get stat of file or directory"""
        return util.parse_attrs(self.session.stat(path))

    @util.reconnect
    def set_stat(self, path: str):
        """Set stat"""
        pass

    @util.reconnect
    def ln(self, path: str, target: str):
        """Create symlink

        :param path: Source path.
        :param target: Target path.
        """
        return self.session.symlink(path, target)

    @util.reconnect
    def unlink(self, path: str):
        """Delete symlink

        :param path: Path to symlink to delete.
        """
        pass

    @util.reconnect
    def get(self, path: str, fh: t.IO):
        """Get file

        :param path: File path to download.
        :param fh: File object to download into.
        """
        pass

    @util.reconnect
    def put(self, fh: t.IO, path: str):
        """Put file

        :param fh: File object for upload.
        :param path: Remote path to upload.
        """
        pass
