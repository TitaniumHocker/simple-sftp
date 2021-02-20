"""Package exceptions"""


class SimpleSFTPBaseError(Exception):
    """Base exception for simple-sftp package"""


class KnownHostsFileNotFoundError(SimpleSFTPBaseError):
    """Failed to find path to hosts file"""


class SockTimeoutError(SimpleSFTPBaseError):
    """Connection timeout reached while creating connection"""


class HostResolveError(SimpleSFTPBaseError):
    """Failed to resolve host"""


class HandShakeFailedError(SimpleSFTPBaseError):
    """Handshake failed"""


class HostValidationError(SimpleSFTPBaseError):
    """Host validation failed"""


class AuthorizationError(SimpleSFTPBaseError):
    """Authorization failed"""


class AgentAuthorizationError(AuthorizationError):
    """Authorization with agent failed"""


class KeyAuthorizationError(AuthorizationError):
    """Authorization with key failed"""


class PasswordAuthorizationError(AuthorizationError):
    """Authorization with password failed"""
