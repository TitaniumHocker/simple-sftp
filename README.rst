###########
simple-sftp
###########

|requires|
|tests|
|codecov|
|codacy|
|codeclimate|

Simple well-typed SFTP(*SSH File Transfer Protocol*) python client based on `ssh2-python <https://github.com/ParallelSSH/ssh2-python>`_ package,
which actually is bindings to *libssh2* C library.

.. contents:: Table of contents

Goals
=====

This project main goal is to provide simple interface for using SFTP.
It's just simple wrapper over `ssh2-python` package and nothing more.

Quickstart
==========

This simple example will print list of files and directories:

.. code:: python
    from simple_sftp import SFTPClient


    with SFTPClient("ssh.example.com", username="root", password="Secret") as sftp:
        print("\n".join(name for name, attr in sftp.ls()))

Installation
============

From PyPI
---------

This package is available on PyPI and can be installed via `pip`.

.. code:: bash

    pip install simple-sftp

From source
-----------

.. code:: bash

    git clone https://github.com/TitaniumHocker/simple-sftp.git
    cd simple-sftp
    python3 setup.py install


Documentation
=============

Documentation of this project is available at `readthedocs <simple-sftp.rtfd.io>`_.


.. |license| image:: https://img.shields.io/github/license/TitaniumHocker/simple-sftp

.. |codecov| image:: https://codecov.io/gh/TitaniumHocker/simple-sftp/branch/master/graph/badge.svg?token=WSDE0HW6E6
   :target: https://codecov.io/gh/TitaniumHocker/simple-sftp

.. |tests| image:: https://github.com/TitaniumHocker/simple-sftp/workflows/Tests/badge.svg

.. |codacy| image:: https://app.codacy.com/project/badge/Grade/48255d770d7349f3936a0090bd909833

.. |codeclimate| image:: https://api.codeclimate.com/v1/badges/4333e9ef5099ad474e5f/maintainability
   :target: https://codeclimate.com/github/TitaniumHocker/simple-sftp/maintainability
   :alt: Maintainability

.. |requires| image:: https://requires.io/github/TitaniumHocker/simple-sftp/requirements.svg?branch=master
   :target: https://requires.io/github/TitaniumHocker/simple-sftp/requirements/?branch=master
   :alt: Requirements Status
