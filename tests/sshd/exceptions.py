class SSHDError(Exception):
    """Base SSHD wrapper exception"""


class SSHDNotFoundError(SSHDError):
    """sshd binary not found"""


class SSHDTemplateError(SSHDError):
    """SSHD template error"""
