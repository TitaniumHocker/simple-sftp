"""Package exceptions"""
import logging

from . import const

logger = logging.getLogger(__name__)


class SFTPError(Exception):
    """Base exception for simple-sftp package"""

    def __init__(self, message: str):
        self.message = message
        logger.error(self.message)
        return super().__init__(self.message)


class SFTPConnectionError(SFTPError):
    """Connection failed"""


class SockTimeoutError(SFTPConnectionError):
    """Connection timeout reached while creating connection"""


class HostResolveError(SFTPConnectionError):
    """Failed to resolve host (dns)"""


class HandshakeError(SFTPConnectionError):
    """Handshake failed"""


class HostValidationError(SFTPConnectionError):
    """Host validation failed"""


class ConnectionDroppedError(SFTPConnectionError):
    """Connection was dropped by remote host"""


class SFTPAuthorizationError(SFTPError):
    """Authorization failed"""


class AgentAuthorizationError(SFTPAuthorizationError):
    """Authorization with agent failed"""


class KeyAuthorizationError(SFTPAuthorizationError):
    """Authorization with key failed"""


class PasswordAuthorizationError(SFTPAuthorizationError):
    """Authorization with password failed"""


class SFTPIOError(SFTPError):
    """Input/output operation failed"""

    def __init__(self, *paths, error: str):
        return super().__init__(
            const.SFTP_IO_ERROR_MESSAGE.format(paths=", ".join(paths), last_error=error)
        )
