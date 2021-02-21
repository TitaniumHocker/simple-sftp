"""Package exceptions"""


class SFTPError(Exception):
    """Base exception for simple-sftp package"""


class ConnectionError(SFTPError):
    """Connection failed"""


class SockTimeoutError(ConnectionError):
    """Connection timeout reached while creating connection"""


class HostResolveError(ConnectionError):
    """Failed to resolve host (dns)"""


class HandshakeError(ConnectionError):
    """Handshake failed"""


class HostValidationError(ConnectionError):
    """Host validation failed"""


class ConnectionDroppedError(ConnectionError):
    """Connection was dropped by remote host"""


class AuthorizationError(SFTPError):
    """Authorization failed"""


class AgentAuthorizationError(AuthorizationError):
    """Authorization with agent failed"""


class KeyAuthorizationError(AuthorizationError):
    """Authorization with key failed"""


class PasswordAuthorizationError(AuthorizationError):
    """Authorization with password failed"""


class SFTPOperationError(SFTPError):
    """Operation failed"""


class PermissionDeniedError(SFTPOperationError):
    """Permission denied"""


class NotFoundError(SFTPOperationError):
    """Requested file or directory not found"""
