#!/usr/bin/env python
# coding: utf-8

from setuptools import setup

# PyPi supports only reStructuredText, so pandoc should be installed
# before uploading package
try:
    import pypandoc
    long_description = pypandoc.convert('README.md', 'rst')
except ImportError:
    long_description = ''


setup(
    name='pypsrp',
    version='0.3.1',
    packages=['pypsrp'],
    install_requires=[
        'cryptography',
        'ntlm-auth>=1.2.0',
        'requests>=2.9.1',
        'six',
    ],
    extras_require={
        ':python_version<"2.7"': [
            'lxml<4.3.0',  # 4.3.0+ has dropped support for Python 2.6
        ],
        ':python_version<="2.7"': [
            'ipaddress',
        ],
        'credssp': [
            'requests-credssp>=1.0.0'
        ],
        'kerberos:sys_platform=="win32"': [
            'pywin32'
        ],
        'kerberos:sys_platform!="win32"': [
            'gssapi>=1.5.0'
        ]
    },
    author='Jordan Borean',
    author_email='jborean93@gmail.com',
    url='https://github.com/jborean93/pypsrp',
    description='PowerShell Remoting Protocol and WinRM for Python',
    long_description=long_description,
    keywords='winrm psrp winrs windows',
    license='MIT',
    python_requires='>=2.6,!=3.0.*,!=3.1.*,!=3.2.*,!=3.3.*',
    classifiers=[
        'Development Status :: 4 - Beta',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.6',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
    ],
)
