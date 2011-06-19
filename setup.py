#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import sys


from setuptools import setup


if sys.argv[-1] == 'publish':
    os.system("python setup.py sdist upload")
    sys.exit()


setup(
    name='httpbin',
    version='110619',
    install_requires=open('reqs.txt').readlines(),
    description='HTTP Request and Response Service.',
    long_description=open('README.md').read(),
    author='Kenneth Reitz',
    author_email='me@kennethreitz.com',
    url='https://httpbin.org',
    packages=['httpbin'],
    license='MIT',
    classifiers=(
        'Development Status :: 5 - Production/Stable',
        'Intended Audience :: Developers',
        'Natural Language :: English',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python',
        # 'Programming Language :: Python :: 2.5',
        'Programming Language :: Python :: 2.6',
        'Programming Language :: Python :: 2.7',
        # 'Programming Language :: Python :: 3.0',
        # 'Programming Language :: Python :: 3.1',
        # 'Programming Language :: Python :: 3.2',
    ),
)
