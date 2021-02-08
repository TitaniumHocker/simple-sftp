"""Authorization methods"""
import typing as t
from abc import ABC, abstractmethod
from getpass import getuser

import ssh2
from ssh2.session import Session

from .excs import (AgentAuthorizationError, AuthorizationError,
                   PasswordAuthorizationError)


class AbstractAuthorization(ABC):
    """Abstract authorization"""
    def auth(self, session: Session):
        """Process authorization for SSH session

        :param session: SSH session"""
        self.authorize(session)
        self.validate(session)

    @abstractmethod
    def authorize(self, session: Session):
        """Authorize SSH session

        :param session: SSH session"""
        pass

    def validate(self, session: Session):
        """Validate that session is authenticated

        :param session: SSH session
        :raise AuthorizationError: If session isn't authorized"""
        if not session.userauth_authenticated():
            raise AuthorizationError(
                "Authorization passed without errors, "
                "but the session remained unauthorized"
            )


class AgentAuthorization(AbstractAuthorization):
    """Agent based authorization

    :param username: User name. Optional, if not provided
        - `getpass.getuser` function will be used instead"""
    def __init__(self, username: t.Optional[str] = None):
        self.username: str = username \
            if username is not None else getuser()

    def authorize(self, session: Session):
        try:
            session.agent_auth(self.username)
        except ssh2.exceptions.AgentConnectionError as exc:
            raise AgentAuthorizationError(
                "Failed to connect to agent"
            ) from exc
        except ssh2.exceptions.AgentListIdentitiesError as exc:
            raise AgentAuthorizationError(
                "Failed to get identities from agent"
            ) from exc
        except ssh2.exceptions.AgentAuthenticationError as exc:
            raise AgentAuthorizationError(
                "Failed to get known identity from agent"
            ) from exc
        except ssh2.exceptions.AgentAuthenticationError as exc:
            raise AgentAuthorizationError(
                "Failed to auth with all identities"
            ) from exc


class KeyAuthorization(AbstractAuthorization):
    def __init__(self, path, passphrase):
        pass

    def authorize(self):
        raise NotImplementedError("Key authorization not implemented yet")


class PasswordAuthorization(AbstractAuthorization):
    """Login and password based authorization

    :param login: Login that will be used for authorization
    :param password: Password that will be used for authorization"""
    def __init__(self, login: str, password: str):
        self.login: str = login
        self.password: str = password

    def authorize(self, session: Session):
        try:
            session.userauth_password(self.login, self.password)
        except ssh2.exceptions.PasswordExpiredError as exc:
            raise PasswordAuthorizationError("Password expired") from exc
        except ssh2.exceptions.AuthenticationError as exc:
            raise PasswordAuthorizationError(
                "Authorization failed, invalid login and/or password"
            ) from exc
