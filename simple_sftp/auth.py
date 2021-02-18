"""Authorization methods"""
import logging
import os
import typing as t
from abc import ABC, abstractmethod
from getpass import getuser

import ssh2
from ssh2.session import Session

from . import excs

logger = logging.getLogger(__name__)


class AbstractAuthorization(ABC):
    """Abstract authorization"""
    def auth(self, session: Session):
        """Process authorization for SSH session

        :param session: SSH session"""
        self.process_authorization(session)
        self.validate_authorization(session)

    @abstractmethod
    def process_authorization(self, session: Session):
        """Authorize SSH session

        :param session: SSH session"""
        pass

    def validate_authorization(self, session: Session):
        """Validate that session is authenticated

        :param session: SSH session
        :raise AuthorizationError: If session isn't authorized"""
        logging.debug("Trying to validate that SSH session is authorized.")
        if not session.userauth_authenticated():
            raise excs.AuthorizationError(
                "Authorization passed without errors, "
                "but the session remained unauthorized"
            )
        logger.debug("SSH session authorization validated.")


class AgentAuthorization(AbstractAuthorization):
    """Agent based authorization handler

    :param username: User name. Optional, if not provided
        `getpass.getuser` function will be used instead."""
    def __init__(self, username: t.Optional[str] = None):
        logger.debug("Creating agent authorization handler.")
        self.username: str = getuser() if username is None else username

    def process_authorization(self, session: Session):
        logger.debug("Trying to authorize SSH session with agent...")
        try:
            session.agent_auth(self.username)
        except ssh2.exceptions.AgentConnectionError as exc:
            raise excs.AgentAuthorizationError(
                "Failed to connect to agent"
            ) from exc
        except ssh2.exceptions.AgentListIdentitiesError as exc:
            raise excs.AgentAuthorizationError(
                "Failed to get identities from agent"
            ) from exc
        except ssh2.exceptions.AgentAuthenticationError as exc:
            raise excs.AgentAuthorizationError(
                "Failed to get known identity from agent"
            ) from exc
        except ssh2.exceptions.AgentAuthenticationError as exc:
            raise excs.AgentAuthorizationError(
                "Failed to auth with all identities"
            ) from exc
        logger.debug("SSH session successfully authorized with agent.")


class KeyAuthorization(AbstractAuthorization):
    """Key authorization handler

    :param path: Path to private key file.
        The path can be either full or relative.
    :param passphrase: Passphrase to unlock key.
        By default is empty string.
    :param username: Username to authenticate as.
        If not provided `getpass.getuser` function
        will be used instead."""
    def __init__(
        self,
        path: str,
        passphrase: str = '',
        username: t.Optional[str] = None
    ):
        logger.debug("Creating key authorization handler.")
        self.username: str = getuser() if username is None else username
        self.path: str = path if path.startswith('/') else os.path.join(os.getcwd(), path)
        self.passphrase: str = passphrase

    def process_authorization(self, session: Session):
        logger.debug("Trying to authorize SSH session with key...")
        session.userauth_publickey_fromfile(self.username, self.path, self.passphrase)
        logger.debug("SSH session successfully authorized with key.")


class PasswordAuthorization(AbstractAuthorization):
    """Login and password authorization handler

    :param login: Login that will be used for authorization.
    :param password: Password that will be used for authorization."""
    def __init__(self, login: str, password: str):
        logger.debug("Creating password authorization handler.")
        self.login: str = login
        self.password: str = password

    def process_authorization(self, session: Session):
        logger.debug("Trying to authorize SSH session with password...")
        try:
            session.userauth_password(self.login, self.password)
        except ssh2.exceptions.PasswordExpiredError as exc:
            raise excs.PasswordAuthorizationError("Password expired") from exc
        except ssh2.exceptions.AuthenticationError as exc:
            raise excs.PasswordAuthorizationError(
                "Authorization failed, invalid login and/or password"
            ) from exc
        logger.debug("SSH session successfully authorized with password.")


AuthHandlersType = t.Union[AgentAuthorization, PasswordAuthorization, KeyAuthorization]
