import os
import socket
from tempfile import TemporaryDirectory
from datetime import datetime

import pytest
from ssh2.session import Session

from simple_sftp import auth, excs, util


@pytest.fixture(scope='function')
def listener():
    sock = socket.socket()
    sock.bind(('localhost', 0))
    sock.listen()
    return sock


def test_decode_permissions(permissions2string):
    for mask, string in permissions2string.items():
        assert util.decode_permissions(mask) == string


def test_encode_permissions(permissions2string, random_string):
    for mask, string in permissions2string.items():
        assert util.encode_permissions(string) == mask

    with pytest.raises(TypeError):
        util.encode_permissions(random_string() + 'abcd')


def test_parse_attrs(initable_sftp_attributes):
    attr = util.parse_attrs(initable_sftp_attributes)

    assert isinstance(attr.mtime, datetime)
    assert attr.mtime == datetime.fromtimestamp(initable_sftp_attributes.mtime)

    assert isinstance(attr.atime, datetime)
    assert attr.atime == datetime.fromtimestamp(initable_sftp_attributes.atime)

    assert isinstance(attr.size, int)
    assert attr.size == initable_sftp_attributes.filesize

    assert isinstance(attr.gid, int)
    assert attr.gid == initable_sftp_attributes.gid
    
    assert isinstance(attr.uid, int)
    assert attr.uid == initable_sftp_attributes.uid

    permissions = util.decode_permissions(initable_sftp_attributes.permissions)
    assert attr.permissions == permissions
    assert attr.type == permissions[0]


def test_find_knownhosts(monkeypatch, random_string):
    tempdir = TemporaryDirectory()
    knownhosts = os.path.join(tempdir.name, '.ssh', 'known_hosts')

    monkeypatch.setattr(util.os.path, 'expanduser', lambda *a, **k: knownhosts)
    monkeypatch.setattr(util, 'getuser', lambda: random_string())
    with pytest.raises(excs.KnownHostsFileNotFoundError):
        util.find_knownhosts()

    os.makedirs(knownhosts)
    assert util.find_knownhosts() == knownhosts

    monkeypatch.setattr(util.os.path, 'expanduser', lambda *a: random_string())
    monkeypatch.setattr(util, 'getuser', lambda: tempdir.name)
    assert util.find_knownhosts() == knownhosts


def test_make_sock(listener):
    sock = util.make_socket(*listener.getsockname(), force_keepalive=True)
    assert sock.getsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE) == 1
    assert isinstance(sock, socket.socket)
    with pytest.raises(excs.HostResolveError):
        util.make_socket('invalid.hostname')
    # TODO: Find out how to test socket timeout


def test_make_ssh_session(sftpserver):
    with sftpserver.serve_content({}):
        session = util.make_ssh_session(
            util.make_socket(sftpserver.host, sftpserver.port),
            # Some shit like paramiko does not support keepalive
            use_keepalive=False
        )
        assert isinstance(session, Session)

        with pytest.raises(excs.HandShakeFailedError):
            util.make_ssh_session(
                util.make_socket(sftpserver.host, sftpserver.port)
            )


def test_pick_auth_method():
    with pytest.raises(TypeError):
        util.pick_auth_method()

    with pytest.raises(TypeError):
        util.pick_auth_method(
            username='aaa',
            password='aaa',
            agent_username='aaa'
        )

    with pytest.raises(TypeError):
        util.pick_auth_method(username='aaa', passphrase='aaa')

    assert isinstance(
        util.pick_auth_method(username='aaa', password='aaa'),
        auth.PasswordAuthorization
    )
    assert isinstance(
        util.pick_auth_method(agent_username='aaa'),
        auth.AgentAuthorization
    )
    assert isinstance(
        util.pick_auth_method(pkey_path='awdad'),
        auth.KeyAuthorization
    )
