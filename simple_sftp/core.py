"""Base class of the package"""
import logging
import os
import typing as t
from hashlib import sha1

import ssh2

from . import auth, const
from . import exceptions as excs
from . import utils

logger = logging.getLogger(__name__)


class SFTP:
    """
    SFTP client

    .. note::
        All arguments except `host` are keyword-only.

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
        passphrase: str = "",
        agent_username: t.Optional[str] = None,
        knownhosts: t.Optional[str] = None,
        validate_host: bool = True,
        knownhosts_autoadd: bool = True,
        session_keepalive: bool = False,
        force_socket_keepalive: bool = False,
        reconnect_on_drop: bool = True,
    ):
        #: Remote host name
        self.host: str = host
        #: Remote host port
        self.port: int = port
        #: Flag to perform host validation or not.
        self.validate_host: bool = validate_host
        #: Path to known_hosts file.
        self.knownhosts: str = (
            knownhosts if knownhosts is not None else utils.find_knownhosts()
        )
        #: New host will be automaticly added to known_hosts file.
        self.knownhosts_autoadd: bool = knownhosts_autoadd
        #: Use SSH session keepalive
        self.session_keepalive: bool = session_keepalive
        #: Force socket keepalive
        self.force_socket_keepalive: bool = force_socket_keepalive
        #: Reconnect if remote host dropped the connection
        self.reconnect_on_drop: bool = reconnect_on_drop
        #: Authorization handaler
        self.auth_handler: auth.AuthHandlersType = utils.pick_auth_method(
            username, password, agent_username, pkey, passphrase
        )
        self._session: ssh2.sftp.SFTP
        self._host_validated: bool = False
        self._cwd: str = "."

    @property
    def cwd(self) -> str:
        """Current working directory"""  # noqa: D401
        return self._cwd

    def _preprocess_path(self, path: str) -> str:
        """Preprocess path

        Translates relative path to cwd relative path.

        :param path: Source path.
        :return: Translated path.
        """
        if path.startswith("/"):
            return path
        return os.path.join(self.cwd, path)

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
                msg = (
                    "Could't read knownhosts file in %s, file seems to be missing. "
                    "A new file will be created on this path when adding a host."
                )
            else:
                msg = (
                    "Could't read knownhosts file in path %s, file seems to be missing."
                )
            logger.warning(msg, self.knownhosts)

        hostkey, keytype = session.hostkey()
        knownhost_typemask = utils.pick_knownhost_typemask(keytype)

        try:
            knownhosts.checkp(
                self.host.encode("utf-8"), self.port, hostkey, knownhost_typemask
            )
            logger.info("Host validation passed.")
        except ssh2.exceptions.KnownHostCheckNotFoundError as e:
            if not self.knownhosts_autoadd:
                raise excs.HostValidationError(
                    f"Host {self.host} not found in knownhosts. "
                    f"Unknown hosts can be autoadded with knownhosts_autoadd=True kwarg."
                ) from e
            logger.info("Adding new host %s to knownhosts file.", self.host)
            knownhosts.addc(
                self.host.encode("utf-8"),
                hostkey,
                knownhost_typemask,
                comment="Added by simple-sftp python package.".encode("utf-8"),
            )
            knownhosts.writefile(self.knownhosts)
            logger.info("Host %s was added to known_hosts file.", self.host)
        except ssh2.exceptions.KnownHostCheckMisMatchError as e:
            raise excs.HostValidationError(
                const.HOSTKEY_VERIFICATION_FAILED_MESSAGE.format(
                    host=self.host,
                    hostkey_hash=sha1(hostkey).hexdigest(),
                    expected_hostkey_hash=sha1(
                        [
                            knownhost.key
                            for knownhost in knownhosts.get()
                            if knownhost.name.decode() == self.host
                        ][0]
                    ).hexdigest(),
                    knownhosts=self.knownhosts,
                    line_number=[
                        i + 1
                        for i, knownhost in enumerate(knownhosts.get())
                        if knownhost.name.decode() == self.host
                    ][0],
                )
            ) from e

        self._host_validated = True

    def connect(self) -> ssh2.sftp.SFTP:
        """Start new SFTP session

        :return: SFTP session.
        """
        ssh_session = utils.make_ssh_session(
            utils.make_socket(
                self.host, self.port, force_keepalive=self.force_socket_keepalive
            ),
            use_keepalive=self.session_keepalive,
        )
        if self.validate_host and not self._host_validated:
            self._process_host_validation(ssh_session)
        self.auth_handler.auth(ssh_session)
        self._session = ssh_session.sftp_init()

        return self._session

    def disconnect(self):
        """Disconnect current session"""
        if hasattr(self, "_session") and isinstance(self._session, ssh2.sftp.SFTP):
            self._session.session.disconnect()
            del self._session

    @property
    def session(self) -> ssh2.sftp.SFTP:
        """Current SFTP session"""  # noqa: D401
        if hasattr(self, "_session") and isinstance(self._session, ssh2.sftp.SFTP):
            return self._session
        self.connect()
        return self._session

    @property
    def session_last_error(self) -> str:
        """Last error of SSH session"""  # noqa: D401
        return self.session.session.last_error().decode("utf-8")

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

    def cd(self, path: str = "~"):
        """Change directory

        Changes the current working directory.

        :param path: Directory to use, can be both relative and absolute.
        :raise SFTPIOError: If can't access requested path(s).
        """
        ppath = self._preprocess_path(path)
        try:
            self.session.stat(ppath)
        except ssh2.exceptions.SFTPProtocolError:
            raise excs.SFTPIOError(path, error=self.session_last_error)
        self._cwd = ppath

    @utils.reconnect
    def realpath(self, path) -> str:
        """Get real path for path

        :param path: Path to get real path for.
        :return: Real path.
        :raise SFTPIOError: If can't access requested path(s).
        """
        ppath = self._preprocess_path(path)
        try:
            return self.session.realpath(ppath)
        except ssh2.exceptions.SFTPProtocolError:
            raise excs.SFTPIOError(path, error=self.session_last_error)

    @utils.reconnect
    def ls(self, path: str = ".") -> t.List[t.Tuple[str, const.FileAttributes]]:
        """Get list of files and directories

        :param path: Path to be listed.
        :return: List of tuples with file/dir names and attributes.
        :raise SFTPIOError: If can't access requested path(s).
        """
        ppath = self._preprocess_path(path)
        try:
            with self.session.opendir(ppath) as dh:
                return [
                    (name.decode("utf-8"), utils.parse_attrs(attrs))
                    for _, name, attrs in dh.readdir()
                ]
        except ssh2.exceptions.SFTPProtocolError:
            raise excs.SFTPIOError(path, error=self.session_last_error)

    @utils.reconnect
    def mv(self, source: str, dest: str):
        """Move/rename file

        :param source: Source path.
        :param dest: Destination path.
        :raise SFTPIOError: If can't access requested path(s).
        """
        psource = self._preprocess_path(source)
        pdest = self._preprocess_path(dest)
        try:
            self.session.rename(psource, pdest)
        except ssh2.exceptions.SFTPProtocolError:
            raise excs.SFTPIOError(source, dest, error=self.session_last_error)

    @utils.reconnect
    def rm(self, path: str):
        """Remove file, symlink or directory

        :param path: Path of file to delete.
        :raise SFTPIOError: If can't access requested path(s).
        """
        if self.get_stat(path).type == "d":
            return self.rmdir(path)

        ppath = self._preprocess_path(path)
        try:
            self.session.unlink(ppath)
        except ssh2.exceptions.SFTPProtocolError:
            raise excs.SFTPIOError(path, error=self.session_last_error)

    @utils.reconnect
    def rmdir(self, path: str):
        """Remove directory

        :param path: Path to directory to remove.
        :raise SFTPIOError: If can't access requested path(s).
        """
        ppath = self._preprocess_path(path)
        try:
            self.session.rmdir(ppath)
        except ssh2.exceptions.SFTPProtocolError:
            raise excs.SFTPIOError(path, error=self.session_last_error)

    @utils.reconnect
    def mkdir(self, path: str, permissions: str = "rwxrwxr-x"):
        """Create directory

        :param path: Path of directory to create.
        :param permissions: Unix-like string with permissions of new directory.
        :raise SFTPIOError: If can't access requested path(s).
        """
        pass

    @utils.reconnect
    def get_stat(self, path: str) -> const.FileAttributes:
        """Get stat of file or directory

        :param path: Path of file or directory to get stat.
        :return: :class:`~const.FileAttributes` instance.
        :raise SFTPIOError: If can't access requested path(s).
        """
        ppath = self._preprocess_path(path)
        try:
            return utils.parse_attrs(self.session.stat(ppath))
        except ssh2.exceptions.SFTPProtocolError:
            raise excs.SFTPIOError(path, error=self.session_last_error)

    @utils.reconnect
    def set_stat(self, path: str):
        """Set stat"""
        pass

    @utils.reconnect
    def ln(self, path: str, target: str):
        """Create symlink

        :param path: Source path.
        :param target: Target path.
        :raise SFTPIOError: If can't access requested path(s).
        """
        ppath = self._preprocess_path(path)
        ptarget = self._preprocess_path(target)
        try:
            self.session.symlink(ppath, ptarget)
        except ssh2.exceptions.SFTPProtocolError:
            raise excs.SFTPIOError(path, target, error=self.session_last_error)

    @utils.reconnect
    def get(self, path: str, fh: t.IO):
        """Get file

        :param path: File path to download.
        :param fh: File object to download into.
        """
        pass

    @utils.reconnect
    def put(self, fh: t.IO, path: str):
        """Put file

        :param fh: File object for upload.
        :param path: Remote path to upload.
        """
        pass
