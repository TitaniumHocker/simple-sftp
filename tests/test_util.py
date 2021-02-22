"""Tests for simple_sftp.utils module"""
import os
import socket
from datetime import datetime
from tempfile import TemporaryDirectory

import pytest
from ssh2.session import Session

from simple_sftp import auth, const
from simple_sftp import exceptions as excs
from simple_sftp import utils


@pytest.fixture(scope="function")
def listener():
    sock = socket.socket()
    sock.bind(("localhost", 0))
    sock.listen()
    return sock


def test_decode_permissions(permissions2string):
    for mask, string in permissions2string.items():
        assert utils.decode_permissions(mask) == string


def test_encode_permissions(permissions2string, random_string):
    for mask, string in permissions2string.items():
        assert utils.encode_permissions(string) == mask

    with pytest.raises(TypeError):
        utils.encode_permissions(random_string() + "abcd")


def test_parse_attrs(initable_sftp_attributes):
    attr = utils.parse_attrs(initable_sftp_attributes)

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

    permissions = utils.decode_permissions(initable_sftp_attributes.permissions)
    assert attr.permissions == permissions
    assert attr.type == permissions[0]

    assert const.UNIX_PERMISSIONS_PATTERN.match(attr.permissions)
    if len(attr.permissions) == 10:
        assert const.UNIX_PERMISSIONS_PATTERN.match(attr.permissions[1::])


def test_find_knownhosts(monkeypatch, random_string):
    tempdir = TemporaryDirectory()
    knownhosts = os.path.join(tempdir.name, ".ssh", "known_hosts")

    randstr = random_string()
    monkeypatch.setattr(utils.os.path, "expanduser", lambda *a, **k: knownhosts)
    monkeypatch.setattr(utils, "getuser", lambda: randstr)
    assert utils.find_knownhosts() == f"/home/{randstr}/.ssh/known_hosts"

    os.makedirs(knownhosts)
    assert utils.find_knownhosts() == knownhosts

    monkeypatch.setattr(utils.os.path, "expanduser", lambda *a: random_string())
    monkeypatch.setattr(utils, "getuser", lambda: tempdir.name)
    assert utils.find_knownhosts() == knownhosts


def test_make_sock(listener):
    sock = utils.make_socket(*listener.getsockname(), force_keepalive=True)
    assert sock.getsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE) == 1
    assert isinstance(sock, socket.socket)
    with pytest.raises(excs.HostResolveError):
        utils.make_socket("invalid.hostname")
    # TODO: Find out how to test socket timeout


def test_make_ssh_session(sftpserver):
    with sftpserver.serve_content({}):
        session = utils.make_ssh_session(
            utils.make_socket(sftpserver.host, sftpserver.port),
            # Some shit like paramiko does not support keepalive
            use_keepalive=False,
        )
        assert isinstance(session, Session)

        with pytest.raises(excs.HandshakeError):
            utils.make_ssh_session(utils.make_socket(sftpserver.host, sftpserver.port))


def test_pick_auth_method():
    with pytest.raises(TypeError):
        utils.pick_auth_method()

    with pytest.raises(TypeError):
        utils.pick_auth_method(username="aaa", password="aaa", agent_username="aaa")

    with pytest.raises(TypeError):
        utils.pick_auth_method(username="aaa", passphrase="aaa")

    assert isinstance(
        utils.pick_auth_method(username="aaa", password="aaa"),
        auth.PasswordAuthorization,
    )
    assert isinstance(
        utils.pick_auth_method(agent_username="aaa"), auth.AgentAuthorization
    )
    assert isinstance(utils.pick_auth_method(pkey_path="awdad"), auth.KeyAuthorization)
