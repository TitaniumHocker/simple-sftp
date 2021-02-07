import io
import os
import re

from setuptools import find_packages, setup


def read(filename):
    filename = os.path.join(os.path.dirname(__file__), filename)
    text_type = type(u"")
    with io.open(filename, mode="r", encoding='utf-8') as file_desc:
        return re.sub(
            text_type(r':[a-z]+:`~?(.*?)`'),
            text_type(r'``\1``'),
            file_desc.read()
        )


setup(
    name="simple-sftp",
    version="0.0.1",
    url="https://github.com/TitaniumHocker/simple-sftp",
    license="MIT",

    author="Ivan Fedorov",
    author_email="inbox@titaniumhocker.ru",

    description="Simple SFTP python client based on ssh2-python package",
    long_description=read("README.rst"),

    project_urls={
        "Documentation": "https://simple-sftp.rtfd.io/",
        "Issue tracker": "https://github.com/TitaniumHocker/simple-sftp/issues",
    },

    packages=find_packages(exclude=('tests', 'docs', 'examples')),

    install_requires=[
        'ssh2-python'
    ],

    classifiers=[
        'Development Status :: 2 - Pre-Alpha'
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Intended Audience :: Developers',
        'Operating System :: POSIX :: Linux',
        'Topic :: Internet',
        'Topic :: Software Development :: Libraries',
        'Topic :: Software Development :: Libraries :: Python Modules',
    ],
)
