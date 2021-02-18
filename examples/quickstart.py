from simple_sftp import SFTPClient


with SFTPClient("ssh.example.com", username="root", password="Secret") as sftp:
    print("\n".join(sftp.ls()))
