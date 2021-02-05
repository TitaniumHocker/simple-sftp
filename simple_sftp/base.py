import logging
import typing as t

import ssh2
from ssh2.session import Session
from ssh2.sftp import SFTP

logger = logging.getLogger(__name__)


class SFTPClient:
    """Simple SFTP client"""
