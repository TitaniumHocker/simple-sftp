"""Package exceptions"""


class SimpleSFTPBaseError(Exception):
    """Base exception for simple-sftp package"""


class SFTPConnectionError(SimpleSFTPBaseError):
    """Connection failed"""


class SockTimeoutError(SFTPConnectionError):
    """Connection timeout reached while creating connection"""


class HostResolveError(SFTPConnectionError):
    """Failed to resolve host"""


class HandShakeFailedError(SFTPConnectionError):
    """Handshake failed"""


class HostValidationError(SFTPConnectionError):
    """Host validation failed"""


class ConnectionDroppedError(SFTPConnectionError):
    """Connection was dropped by remote host"""


class SFTPAuthorizationError(SimpleSFTPBaseError):
    """Authorization failed"""


class AgentAuthorizationError(SFTPAuthorizationError):
    """Authorization with agent failed"""


class KeyAuthorizationError(SFTPAuthorizationError):
    """Authorization with key failed"""


class PasswordAuthorizationError(SFTPAuthorizationError):
    """Authorization with password failed"""


class SFTPOperationError(SimpleSFTPBaseError):
    """Operation failed"""


class PermissionDeniedError(SFTPOperationError):
    """Permission denied"""


class ChangingDirectoryError(SFTPOperationError):
    """Can't change current working directory"""


class NotFoundError(SFTPOperationError):
    """Requested file or directory not found"""
