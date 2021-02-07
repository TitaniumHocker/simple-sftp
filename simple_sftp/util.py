"""Helper functions, decorators and another stuff"""
import logging
import os
import socket
import typing as t
from getpass import getuser

import ssh2
from ssh2.session import Session

from .excs import (HandShakeFailedError, HostResolveError,
                   KnownHostsFileNotFoundError, SockTimeoutError)

logger = logging.getLogger(__name__)


def find_knownhosts() -> str:
    """Get known_hosts file full path

    :return: Full path to known_hosts file.
    :raise KnownHostsNotFoundError: If
        failed to find full path to known_hosts file."""
    relative_path: str = os.path.join('~', '.ssh', 'known_hosts')
    full_path: str = os.path.expanduser(relative_path)
    if relative_path != full_path and full_path.startswith('/') \
            and os.path.exists(full_path):
        return full_path
    dummy_path = os.path.join('/home', getuser(), '.ssh', 'known_hosts')
    if os.path.exists(dummy_path):
        return dummy_path
    raise KnownHostsFileNotFoundError("Failed to find known_hosts file.")


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
    """Make prepared socket

    Creates socket prepared for usage. If needed sets
    keep alive socket options directly on the socket.

    :param host: Host to connect.
    :param port: Port number to use.
    :param connection_timeout: Connection timeout
        in seconds. Optional, by default is `10.0` seconds.
    :param force_keepalive: Flag for forcing socket
        keepalive options. Default is `False`.
    :param keepalive_options: Dictionary with keepalive
        options that will be used if `force_keepalive`
        is set to `True`. Keys of the dictionary is
        keepalive options constants from `socket` package.
        For example `socket.TCP_KEEPIDLE`.
    :raise HostResolveError: If host resolving was unsuccessfull.
    :raise SockTimeoutError: If connection timeout has been reached.
    :return: New configured socket."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(connection_timeout)

    if force_keepalive:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        for key, value in keepalive_options.items():
            sock.setsockopt(socket.IPPROTO_TCP, key, value)

    try:
        sock.connect((host, port))
    except socket.gaierror as exc:
        raise HostResolveError(
            f"Failed to resolve host {host} into IP adress."
        )from exc
    except socket.timeout as exc:
        raise SockTimeoutError(
            f"Connection timeout reached while trying "
            f"to establish connection to {host}:{port}"
        ) from exc

    return sock


def make_ssh_session(sock: socket.socket, retry_count: int = 3) -> Session:
    """Create ssh session from existing socket

    :param sock: Socket to use for SSH session.
    :param retry_count: Count of max handshake
        retries. By default is set to 3.
    :param HandShakeFailedError: If ssh handshake fails.
    :return: SSH Session."""
    ssh: Session = Session()
    ssh.set_blocking(True)
    ssh.keepalive_config(True, 3)

    for i in range(1, 3 + 1):
        try:
            ssh.handshake(sock)
            break
        except ssh2.exceptions.KeyExchangeError as exc:
            if i < retry_count:
                continue
            raise HandShakeFailedError("SSH handshake failed") from exc
        except (ssh2.exceptions.SocketDisconnectError,
                ssh2.exceptions.SocketRecvError,
                ssh2.exceptions.SocketSendError) as exc:
            raise HandShakeFailedError(
                "Connection seems to be closed by remote host"
            ) from exc

    return ssh
