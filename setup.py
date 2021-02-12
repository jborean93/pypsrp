#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Copyright: (c) 2020 Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import os

from setuptools import setup


def abs_path(rel_path):
    return os.path.join(os.path.dirname(__file__), rel_path)


with open(abs_path('README.md'), mode='rb') as fd:
    long_description = fd.read().decode('utf-8')


setup(
    name='pypsrp',
    version='1.0.0',
    packages=[
        'pypsrp',
        'pypsrp.pwsh_scripts',
        'psrp',
        'psrp.dotnet',
        'psrp.io',
        'psrp.protocol',
    ],
    include_package_data=True,
    install_requires=[
        'cryptography',
        'httpx',
        'pyspnego',
    ],
    extras_require={
        ':python_version<"3.7"': {
            'async_generator',
        },
        'kerberos:sys_platform=="win32"': [],
        'kerberos:sys_platform!="win32"': [
            'gssapi>=1.5.0'
        ]
    },
    author='Jordan Borean',
    author_email='jborean93@gmail.com',
    url='https://github.com/jborean93/pypsrp',
    description='PowerShell Remoting Protocol and WinRM for Python',
    long_description=long_description,
    long_description_content_type='text/markdown',
    keywords='winrm psrp winrs windows powershell',
    license='MIT',
    python_requires='>=3.6',
    classifiers=[
        'Development Status :: 4 - Beta',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
    ],
)
