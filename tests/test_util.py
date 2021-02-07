import os
import socket
from tempfile import TemporaryDirectory

import pytest
from ssh2.session import Session

from simple_sftp import excs, util


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


def test_make_sock(listener):
    sock = util.make_socket(*listener.getsockname(), force_keepalive=True)
    assert sock.getsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE) == 1
    assert isinstance(sock, socket.socket)
    # TODO: Find out how to test socket timeout.


def test_make_ssh_session(sftpserver):
    with sftpserver.serve_content({}):
        assert isinstance(
            util.make_ssh_session(
                util.make_socket(sftpserver.host, sftpserver.port)
            ),
            Session
        )
