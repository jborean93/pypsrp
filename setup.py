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
    version='0.0.1',
    packages=['pypsrp'],
    install_requires=[
        'requests',
        'six',
    ],
    extras_require={
        ':python_version<"2.7"': [
            'lxml',
        ],
        'crypto': [
            'cryptography',
        ]
    },
    author='Jordan Borean',
    author_email='jborean93@gmail.com',
    url='https://github.com/jborean93/pypsrp',
    description='PowerShell Remoting Protocol and WinRM for Python',
    long_description=long_description,
    keywords='winrm psrp winrs windows',
    license='MIT',
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
    ],
)
