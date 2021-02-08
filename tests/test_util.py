import os
import socket
from tempfile import TemporaryDirectory

import pytest
from ssh2.session import Session

from simple_sftp import auth, excs, util


@pytest.fixture(scope='function')
def listener():
    sock = socket.socket()
    sock.bind(('localhost', 0))
    sock.listen()
    return sock


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
