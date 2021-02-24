"""Global conftest"""
from random import choice
from string import ascii_letters

import mockssh
import pytest
from factory import Factory, Faker
from pytest_factoryboy import register
from ssh2.sftp import LIBSSH2_SFTP_S_IFBLK as IFBLK
from ssh2.sftp import LIBSSH2_SFTP_S_IFCHR as IFCHR
from ssh2.sftp import LIBSSH2_SFTP_S_IFDIR as IFDIR
from ssh2.sftp import LIBSSH2_SFTP_S_IFIFO as IFIFO
from ssh2.sftp import LIBSSH2_SFTP_S_IFLNK as IFLNK
from ssh2.sftp import LIBSSH2_SFTP_S_IFREG as IFREG
from ssh2.sftp import LIBSSH2_SFTP_S_IFSOCK as IFSOCK
from ssh2.sftp import LIBSSH2_SFTP_S_IRGRP as IRGRP
from ssh2.sftp import LIBSSH2_SFTP_S_IROTH as IROTH
from ssh2.sftp import LIBSSH2_SFTP_S_IRUSR as IRUSR
from ssh2.sftp import LIBSSH2_SFTP_S_IWGRP as IWGRP
from ssh2.sftp import LIBSSH2_SFTP_S_IWOTH as IWOTH
from ssh2.sftp import LIBSSH2_SFTP_S_IWUSR as IWUSR
from ssh2.sftp import LIBSSH2_SFTP_S_IXGRP as IXGRP
from ssh2.sftp import LIBSSH2_SFTP_S_IXOTH as IXOTH
from ssh2.sftp import LIBSSH2_SFTP_S_IXUSR as IXUSR
from ssh2.sftp_handle import SFTPAttributes


@pytest.fixture(scope="session")
def random_string():
    return lambda: "".join(choice(ascii_letters) for _ in range(10))


@pytest.fixture(scope="session")
def ssh_server():
    with mockssh.Server({}) as server:
        yield server


PERMISSIONS2STRING_MAP = {
    IFBLK | IRUSR | IWUSR | IXUSR: "brwx------",
    IFCHR | IRGRP | IWGRP | IXGRP: "c---rwx---",
    IFIFO | IROTH | IWOTH | IXOTH: "p------rwx",
    IFLNK | IRUSR | IWGRP | IXOTH: "lr---w---x",
    IFDIR | IRUSR | IWUSR | IXUSR | IRGRP | IWGRP | IXGRP | IROTH | IXOTH: "drwxrwxr-x",
    IFREG | IRUSR | IWUSR | IRGRP | IWGRP | IROTH: "-rw-rw-r--",
    IFREG | IRUSR | IWUSR | IXUSR | IRGRP | IWGRP | IXGRP | IROTH: "-rwxrwxr--",
    IRUSR | IWUSR | IRGRP | IWGRP | IROTH: "rw-rw-r--",
    IFSOCK | IRUSR | IWUSR | IXUSR | IRGRP | IWGRP | IXGRP: "srwxrwx---",
    IFREG | IRGRP | IROTH | IWOTH | IXOTH: "----r--rwx",
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
