from random import choice
from string import ascii_letters

from factory import Faker, Factory
from pytest_factoryboy import register
import pytest
from ssh2.sftp_handle import SFTPAttributes
from ssh2.sftp import LIBSSH2_SFTP_S_IFBLK as IFBLK # ftype: Block special (block device)
from ssh2.sftp import LIBSSH2_SFTP_S_IFCHR as IFCHR  # ftype: Character special (character device)
from ssh2.sftp import LIBSSH2_SFTP_S_IFDIR as IFDIR  # ftype: Directory
from ssh2.sftp import LIBSSH2_SFTP_S_IFIFO as IFIFO  # ftype: Named pipe (fifo)
from ssh2.sftp import LIBSSH2_SFTP_S_IFLNK as IFLNK  # ftype: Symbolic link
from ssh2.sftp import LIBSSH2_SFTP_S_IFREG as IFREG   # ftype: Regular file
from ssh2.sftp import LIBSSH2_SFTP_S_IFSOCK as IFSOCK  # ftype: Socket
from ssh2.sftp import LIBSSH2_SFTP_S_IRGRP as IRGRP  # group: Read
from ssh2.sftp import LIBSSH2_SFTP_S_IROTH as IROTH  # other: Read
from ssh2.sftp import LIBSSH2_SFTP_S_IRUSR as IRUSR  # owner: Read
from ssh2.sftp import LIBSSH2_SFTP_S_IWGRP as IWGRP  # group: Write
from ssh2.sftp import LIBSSH2_SFTP_S_IWOTH as IWOTH  # other: Write
from ssh2.sftp import LIBSSH2_SFTP_S_IWUSR as IWUSR  # owner: Write
from ssh2.sftp import LIBSSH2_SFTP_S_IXGRP as IXGRP  # group: Execute
from ssh2.sftp import LIBSSH2_SFTP_S_IXOTH as IXOTH  # other: Execute
from ssh2.sftp import LIBSSH2_SFTP_S_IXUSR as IXUSR  # owner: Execute


@pytest.fixture(scope="session")
def random_string():
    return lambda: "".join(choice(ascii_letters) for _ in range(10))


PERMISSIONS2STRING_MAP = {
    IFDIR | IRUSR | IWUSR | IXUSR | IRGRP | IWGRP | IXGRP | IROTH | IXOTH: "drwxrwxr-x",
    IFREG | IRUSR | IWUSR | IRGRP | IWGRP | IROTH: "-rw-rw-r--",
    IFREG | IRUSR | IWUSR | IXUSR | IRGRP | IWGRP | IXGRP | IROTH: "-rwxrwxr--",
    IRUSR | IWUSR | IRGRP | IWGRP | IROTH: "rw-rw-r--",
    IFSOCK | IRUSR | IWUSR | IXUSR | IRGRP | IWGRP | IXGRP: "srwxrwx---",
    IFREG | IRGRP | IROTH | IWOTH | IXOTH: "----r--rwx"
}


@pytest.fixture(scope="session")
def permissions2string():
    return PERMISSIONS2STRING_MAP


class InitableSFTPAttributes(SFTPAttributes):
    def __init__(self, atime, mtime, uid, gid, filesize, *args, **kwargs):
        self.atime = atime
        self.mtime = mtime
        self.uid = uid
        self.gid = gid
        self.filesize = filesize
        self.permissions = choice(list(PERMISSIONS2STRING_MAP.keys()))


@register
class SFTPAttributesFactory(Factory):
    class Meta:
        model = InitableSFTPAttributes
    
    atime = Faker("unix_time")
    mtime = Faker("unix_time")
    uid = Faker("random_int")
    gid = Faker("random_int")
    filesize = Faker("random_int")
