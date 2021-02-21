"""Helper functions, decorators and another stuff"""
import functools
import logging
import os
import re
import socket
import typing as t
from datetime import datetime
from getpass import getuser

import ssh2
from ssh2.knownhost import (
    LIBSSH2_KNOWNHOST_KEY_ECDSA_256,
    LIBSSH2_KNOWNHOST_KEY_ECDSA_384,
    LIBSSH2_KNOWNHOST_KEY_ECDSA_521,
    LIBSSH2_KNOWNHOST_KEY_SSHDSS,
    LIBSSH2_KNOWNHOST_KEY_SSHRSA,
    LIBSSH2_KNOWNHOST_KEYENC_RAW,
    LIBSSH2_KNOWNHOST_TYPE_PLAIN,
)
from ssh2.session import (
    LIBSSH2_HOSTKEY_TYPE_DSS,
    LIBSSH2_HOSTKEY_TYPE_ECDSA_256,
    LIBSSH2_HOSTKEY_TYPE_ECDSA_384,
    LIBSSH2_HOSTKEY_TYPE_ECDSA_521,
    LIBSSH2_HOSTKEY_TYPE_RSA,
    Session,
)
from ssh2.sftp import LIBSSH2_SFTP_S_IFBLK  # ftype: Block special (block device)
from ssh2.sftp import LIBSSH2_SFTP_S_IFCHR  # ftype: Character special (character device)
from ssh2.sftp import LIBSSH2_SFTP_S_IFDIR  # ftype: Directory
from ssh2.sftp import LIBSSH2_SFTP_S_IFIFO  # ftype: Named pipe (fifo)
from ssh2.sftp import LIBSSH2_SFTP_S_IFLNK  # ftype: Symbolic link
from ssh2.sftp import LIBSSH2_SFTP_S_IFREG  # ftype: Regular file
from ssh2.sftp import LIBSSH2_SFTP_S_IFSOCK  # ftype: Socket
from ssh2.sftp import LIBSSH2_SFTP_S_IRGRP  # group: Read
from ssh2.sftp import LIBSSH2_SFTP_S_IROTH  # other: Read
from ssh2.sftp import LIBSSH2_SFTP_S_IRUSR  # owner: Read
from ssh2.sftp import LIBSSH2_SFTP_S_IWGRP  # group: Write
from ssh2.sftp import LIBSSH2_SFTP_S_IWOTH  # other: Write
from ssh2.sftp import LIBSSH2_SFTP_S_IWUSR  # owner: Write
from ssh2.sftp import LIBSSH2_SFTP_S_IXGRP  # group: Execute
from ssh2.sftp import LIBSSH2_SFTP_S_IXOTH  # other: Execute
from ssh2.sftp import LIBSSH2_SFTP_S_IXUSR  # owner: Execute
from ssh2.sftp_handle import SFTPAttributes

from . import auth, excs

logger = logging.getLogger(__name__)


HOSTKEY_VERIFICATION_FAILED_MESSAGE = """
Host key verification for {host} failed.
Someone could be eavesdropping on you right now (man-in-the-middle attack)!
It is also possible that the host key has just been changed.
The fingerprint for the key sent by the remote host is {hostkey_hash}.
Expected fingerprint is {expected_hostkey_hash}.
Add correct host key in {knownhosts} to get rid of this message.
Offending key in {knownhosts}:{line_number}.

If you are sure that the key has been changed and this is not MITM attack,
then you can delete the old key with the following command:
    ssh-keygen -R {host} -f {knownhosts}
"""


HOMEDIR_PATTERN = re.compile(r'^(\/home\/\w+)$')
RWX_PATTERN = re.compile(r"^([rwx]{3})$")


HOSTKEYTYPE_MAP: t.Dict[int, int] = {
    LIBSSH2_HOSTKEY_TYPE_DSS: LIBSSH2_KNOWNHOST_KEY_SSHDSS,
    LIBSSH2_HOSTKEY_TYPE_RSA: LIBSSH2_KNOWNHOST_KEY_SSHRSA,
    LIBSSH2_HOSTKEY_TYPE_ECDSA_256: LIBSSH2_KNOWNHOST_KEY_ECDSA_256,
    LIBSSH2_HOSTKEY_TYPE_ECDSA_384: LIBSSH2_KNOWNHOST_KEY_ECDSA_384,
    LIBSSH2_HOSTKEY_TYPE_ECDSA_521: LIBSSH2_KNOWNHOST_KEY_ECDSA_521
}


FILETYPE_MASKS: t.List[int] = [
    LIBSSH2_SFTP_S_IFSOCK,
    LIBSSH2_SFTP_S_IFBLK,
    LIBSSH2_SFTP_S_IFCHR,
    LIBSSH2_SFTP_S_IFDIR,
    LIBSSH2_SFTP_S_IFIFO,
    LIBSSH2_SFTP_S_IFLNK,
    LIBSSH2_SFTP_S_IFREG
]


PERMISSIONS_MASKS: t.List[int] = [
    LIBSSH2_SFTP_S_IRUSR,
    LIBSSH2_SFTP_S_IWUSR,
    LIBSSH2_SFTP_S_IXUSR,
    LIBSSH2_SFTP_S_IRGRP,
    LIBSSH2_SFTP_S_IWGRP,
    LIBSSH2_SFTP_S_IXGRP,
    LIBSSH2_SFTP_S_IROTH,
    LIBSSH2_SFTP_S_IWOTH,
    LIBSSH2_SFTP_S_IXOTH
]

MASK2SIGN_MAP: t.Dict[int, str] = {
    LIBSSH2_SFTP_S_IFBLK: "b",
    LIBSSH2_SFTP_S_IFCHR: "c",
    LIBSSH2_SFTP_S_IFDIR: "d",
    LIBSSH2_SFTP_S_IFIFO: "p",
    LIBSSH2_SFTP_S_IFLNK: "l",
    LIBSSH2_SFTP_S_IFREG: "-",
    LIBSSH2_SFTP_S_IFSOCK: "s",
    LIBSSH2_SFTP_S_IRGRP: "r",
    LIBSSH2_SFTP_S_IROTH: "r",
    LIBSSH2_SFTP_S_IRUSR: "r",
    LIBSSH2_SFTP_S_IWGRP: "w",
    LIBSSH2_SFTP_S_IWOTH: "w",
    LIBSSH2_SFTP_S_IWUSR: "w",
    LIBSSH2_SFTP_S_IXGRP: "x",
    LIBSSH2_SFTP_S_IXOTH: "x",
    LIBSSH2_SFTP_S_IXUSR: "x"
}


UNIX_PERMISSIONS_PATTERN = re.compile(r"^(([bcdpl\-s])?((\-|r)(\-|w)(\-|x)){3})$", re.I)


def decode_permissions(permissions: int) -> str:
    """
    Decode permissions

    Decodes permissions bitmask into Unix-like permissions string.

    :param permissions: Permissions bitmask.
    :return: Unix-like permissions string.
    """
    result = ""

    for mask in FILETYPE_MASKS:
        if permissions & mask == mask:
            result += MASK2SIGN_MAP[mask]
            break

    for mask in PERMISSIONS_MASKS:
        if permissions & mask == mask:
            result += MASK2SIGN_MAP[mask]
        else:
            result += "-"

    return result


def encode_permissions(permissions: str) -> int:
    """
    Encode permissions

    Encodes permissions Unix-like string into permissions bitmask that
    can be used with ssh2-python package(libssh2).

    :param permissions: Unix-like permissions string.
    :return: Persmissions bitmask.
    :raise TypeError: If incorrect permissions string was provided.
    """
    if not UNIX_PERMISSIONS_PATTERN.match(permissions):
        raise TypeError("Incorrect permissions string.")

    result = 0

    if len(permissions) == 10:
        for mask in FILETYPE_MASKS:
            if MASK2SIGN_MAP[mask] == permissions[0]:
                result |= mask
                permissions = permissions[1::]
                break

    for i, mask in enumerate(PERMISSIONS_MASKS):
        if MASK2SIGN_MAP[mask] == permissions[i]:
            result |= mask

    return result


class FileAttributes(t.NamedTuple):
    """File attributes"""
    atime: datetime
    mtime: datetime
    size: int
    uid: int
    gid: int
    permissions: str

    @property
    def type(self) -> str:
        """Filetype sign"""
        return self.permissions[0]


def parse_attrs(attrs: SFTPAttributes) -> FileAttributes:
    """Parse attributes

    :param attrs: Instalnse of `SFTPAttributes`.
    :return: Instance of `FileAttributes`.
    """
    return FileAttributes(
        atime=datetime.fromtimestamp(attrs.atime),
        mtime=datetime.fromtimestamp(attrs.mtime),
        size=attrs.filesize,
        uid=attrs.uid,
        gid=attrs.gid,
        permissions=decode_permissions(attrs.permissions)
    )


def reconnect(func: t.Callable) -> t.Callable:
    """Reconnect on connection drop

    Decorator to reconnect when connection was dropped by remote host.

    :param func: Method of `simple_sftp.SFTP`.
    :return: Decored method.
    """
    @functools.wraps(func)
    def inner(self, *args, **kwargs):
        try:
            return func(self, *args, **kwargs)
        except ssh2.exceptions.SocketRecvError as exc:
            if not self.reconnect_on_drop:
                raise excs.ConnectionDroppedError(
                    "Connection seems to by remote host"
                ) from exc
        logger.warning("Connection was dropped by remote host, reconnecting...")
        self.connect()
        return func(self, *args, **kwargs)
    return inner


def find_knownhosts() -> str:
    """
    Get known_hosts file full path

    Searches for known hosts file in `~/.ssh` directory.

    :return: Full path to known_hosts file.
    """
    relative_path: str = os.path.join('~', '.ssh', 'known_hosts')
    full_path: str = os.path.expanduser(relative_path)
    if relative_path != full_path and full_path.startswith('/') \
            and os.path.exists(full_path):
        return full_path
    return os.path.join('/home', getuser(), '.ssh', 'known_hosts')


def pick_knownhost_typemask(hostkey_type: int) -> int:
    """Pick knownhost typemask

    :param hostkey_type: Type of remote host key.
    :return: Typemask for checking in known_hosts file.
    """
    return LIBSSH2_KNOWNHOST_TYPE_PLAIN | \
        LIBSSH2_KNOWNHOST_KEYENC_RAW | HOSTKEYTYPE_MAP[hostkey_type]


def make_socket(
    host: str,
    port: int = 22,
    connection_timeout: float = 10.0,
    force_keepalive: bool = False,
    keepalive_options: t.Dict[int, int] = {
        socket.TCP_KEEPIDLE: 1,
        socket.TCP_KEEPINTVL: 3,
        socket.TCP_KEEPCNT: 3
    }
) -> socket.socket:
    """
    Make prepared socket

    Creates socket prepared for usage. If needed sets
    keep alive socket options directly on the socket.

    :param host: Host to connect.
    :param port: Port number to use.
    :param connection_timeout: Connection timeout in seconds.
        Optional, by default is `10.0` seconds.
    :param force_keepalive: Flag for forcing socket keepalive options. Default is `False`.
    :param keepalive_options: Dictionary with keepalive options that will be used if
        `force_keepalive` is set to `True`. Keys of the dictionary is keepalive options constants
        from `socket` package. For example `socket.TCP_KEEPIDLE`.
    :raise HostResolveError: If host resolving was unsuccessfull.
    :raise SockTimeoutError: If connection timeout has been reached.
    :return: New configured socket.
    """
    logger.debug("Creating new socket with timeout %f.", connection_timeout)
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(connection_timeout)

    if force_keepalive:
        logger.info("Forcing socket keepalive configuration.")
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        for key, value in keepalive_options.items():
            sock.setsockopt(socket.IPPROTO_TCP, key, value)

    logger.debug("Trying to connect socket to %s:%i...", host, port)

    try:
        sock.connect((host, port))
    except socket.gaierror as exc:
        raise excs.HostResolveError(
            f"Failed to resolve host {host} into IP adress."
        )from exc
    except socket.timeout as exc:
        raise excs.SockTimeoutError(
            f"Connection timeout reached while trying "
            f"to establish connection to {host}:{port}"
        ) from exc

    logger.debug("Socket successfully connected.")

    return sock


def make_ssh_session(
    sock: socket.socket,
    retry_count: int = 3,
    use_keepalive: bool = True
) -> Session:
    """
    Create ssh session from existing socket

    :param sock: Socket to use for SSH session.
    :param retry_count: Count of max handshake retries. By default is set to 3.
    :raise HandShakeFailedError: If SSH handshake fails.
    :return: SSH Session.
    """
    logger.debug("Creating new SSH session from provided socket.")
    ssh: Session = Session()
    ssh.set_blocking(True)
    if use_keepalive:
        logger.info("Settingup SSH session keepalive configuration.")
        ssh.keepalive_config(True, 3)

    logger.debug("Making SSH handshake...")
    for i in range(1, retry_count + 2):
        try:
            ssh.handshake(sock)
            break
        except ssh2.exceptions.KeyExchangeError as exc:
            if i <= retry_count:
                logger.warning("%i attempt failed, will try again.", i)
                continue
            logger.warning("%i attempt failed, will raise an exception.", i)
            raise excs.HandShakeFailedError("SSH handshake failed") from exc
        except (ssh2.exceptions.SocketDisconnectError,
                ssh2.exceptions.SocketRecvError,
                ssh2.exceptions.SocketSendError) as exc:
            raise excs.HandShakeFailedError(
                "Connection seems to be closed by remote host"
            ) from exc

    logger.debug("SSH handshake successfully made.")
    return ssh


def pick_auth_method(
    username: t.Optional[str] = None,
    password: t.Optional[str] = None,
    agent_username: t.Optional[str] = None,
    pkey_path: t.Optional[str] = None,
    passphrase: str = ''
) -> auth.AuthHandlersType:
    """Pick authorization method from provided credentials

    :param username: Username for username/password authorization.
    :param password: Password for username/password authorization.
    :param agent_username: Username for agent authorization.
    :param pkey_path: Path to private key for key authorization.
    :param passphrase: Passphrase for key authorization.
    :raise TypeError: If credentials for multiple authorization types was provided or not enough
        credentials was provided to pick at least one authorization handler.
    :return: Initialized authorization handler.
    """
    logger.debug("Trying to pick authorization method from provided credentials")

    if username is None and password is None and \
            agent_username is None and pkey_path is None:
        raise TypeError("Not enough credentials was provided.")

    if len([i for i in [
        username and password, agent_username, pkey_path
    ] if i is not None]) > 1:
        raise TypeError("Too many credentials was provided.")

    if username is not None and password is not None:
        logger.debug("Password authorization method picked.")
        return auth.PasswordAuthorization(username, password)

    if agent_username is not None:
        logger.debug("Agent authorization method picked.")
        return auth.AgentAuthorization(agent_username)

    if pkey_path is not None:
        logger.debug("Key authorization method picked.")
        return auth.KeyAuthorization(pkey_path, passphrase)

    raise TypeError("Failed to pick authorization type.")


def walk(path: str) -> t.List[str]:
    """Walk through directories

    :param path: Path to traget directory.
    :return: List of paths to walk
    """
    def inner(path: str) -> t.List[str]:
        paths = [path]
        head, tail = os.path.split(path)
        if head:
            paths.extend(inner(head))
        return paths
    return list(reversed(inner(path)))
