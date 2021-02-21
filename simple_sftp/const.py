"""Constants of the package"""
import re
import typing as t
from datetime import datetime

from ssh2.knownhost import (
    LIBSSH2_KNOWNHOST_KEY_ECDSA_256,
    LIBSSH2_KNOWNHOST_KEY_ECDSA_384,
    LIBSSH2_KNOWNHOST_KEY_ECDSA_521,
    LIBSSH2_KNOWNHOST_KEY_SSHDSS,
    LIBSSH2_KNOWNHOST_KEY_SSHRSA,
)
from ssh2.session import (
    LIBSSH2_HOSTKEY_TYPE_DSS,
    LIBSSH2_HOSTKEY_TYPE_ECDSA_256,
    LIBSSH2_HOSTKEY_TYPE_ECDSA_384,
    LIBSSH2_HOSTKEY_TYPE_ECDSA_521,
    LIBSSH2_HOSTKEY_TYPE_RSA,
)
from ssh2.sftp import (
    LIBSSH2_SFTP_S_IFBLK,
    LIBSSH2_SFTP_S_IFCHR,
    LIBSSH2_SFTP_S_IFDIR,
    LIBSSH2_SFTP_S_IFIFO,
    LIBSSH2_SFTP_S_IFLNK,
    LIBSSH2_SFTP_S_IFREG,
    LIBSSH2_SFTP_S_IFSOCK,
    LIBSSH2_SFTP_S_IRGRP,
    LIBSSH2_SFTP_S_IROTH,
    LIBSSH2_SFTP_S_IRUSR,
    LIBSSH2_SFTP_S_IWGRP,
    LIBSSH2_SFTP_S_IWOTH,
    LIBSSH2_SFTP_S_IWUSR,
    LIBSSH2_SFTP_S_IXGRP,
    LIBSSH2_SFTP_S_IXOTH,
    LIBSSH2_SFTP_S_IXUSR,
)

HOSTKEY_VERIFICATION_FAILED_MESSAGE = """
Host key verification for {host} failed.
Someone could be eavesdropping on you right now (man-in-the-middle attack)!
It is also possible that the host key has just been changed.
The fingerprint for the key sent by the remote host is {hostkey_hash}.
Expected fingerprint is {expected_hostkey_hash}.
Add correct host key in {knownhosts} to get rid of this message.
Offending key in {knownhosts}:{line_number}.

If you are sure that the key has been changed and this is not MITM attack,
then you can delete the old key from known hosts with the following command:
    ssh-keygen -R {host} -f {knownhosts}
"""

SFTP_IO_ERROR_MESSAGE = """
IO operation failed.
Can't access {paths}: file doesn't exists or not enough permissions.
SSH session last error: {last_error}
"""

UNIX_PERMISSIONS_PATTERN = re.compile(r"^(([bcdpl\-s])?((\-|r)(\-|w)(\-|x)){3})$", re.I)


HOSTKEYTYPE_MAP: t.Dict[int, int] = {
    LIBSSH2_HOSTKEY_TYPE_DSS: LIBSSH2_KNOWNHOST_KEY_SSHDSS,
    LIBSSH2_HOSTKEY_TYPE_RSA: LIBSSH2_KNOWNHOST_KEY_SSHRSA,
    LIBSSH2_HOSTKEY_TYPE_ECDSA_256: LIBSSH2_KNOWNHOST_KEY_ECDSA_256,
    LIBSSH2_HOSTKEY_TYPE_ECDSA_384: LIBSSH2_KNOWNHOST_KEY_ECDSA_384,
    LIBSSH2_HOSTKEY_TYPE_ECDSA_521: LIBSSH2_KNOWNHOST_KEY_ECDSA_521,
}


FILETYPE_MASKS: t.List[int] = sorted(
    [
        LIBSSH2_SFTP_S_IFSOCK,
        LIBSSH2_SFTP_S_IFBLK,
        LIBSSH2_SFTP_S_IFCHR,
        LIBSSH2_SFTP_S_IFDIR,
        LIBSSH2_SFTP_S_IFIFO,
        LIBSSH2_SFTP_S_IFLNK,
        LIBSSH2_SFTP_S_IFREG,
    ],
    reverse=True,
)


PERMISSIONS_MASKS: t.List[int] = [
    LIBSSH2_SFTP_S_IRUSR,
    LIBSSH2_SFTP_S_IWUSR,
    LIBSSH2_SFTP_S_IXUSR,
    LIBSSH2_SFTP_S_IRGRP,
    LIBSSH2_SFTP_S_IWGRP,
    LIBSSH2_SFTP_S_IXGRP,
    LIBSSH2_SFTP_S_IROTH,
    LIBSSH2_SFTP_S_IWOTH,
    LIBSSH2_SFTP_S_IXOTH,
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
    LIBSSH2_SFTP_S_IXUSR: "x",
}


class FileAttributes(t.NamedTuple):
    """File attributes"""

    #: Access time
    atime: datetime
    #: Modify time
    mtime: datetime
    #: File size in bytes
    size: int
    #: User(owner) id
    uid: int
    #: Group id
    gid: int
    #: Unix-like permissions string
    permissions: str

    @property
    def type(self) -> str:
        """Filetype sign"""
        return self.permissions[0]
