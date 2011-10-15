#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import sys

try:
    from setuptools import setup
except ImportError:
    from distutils.core import setup


if sys.argv[-1] == 'publish':
    os.system("python setup.py sdist upload")
    sys.exit()


deps = [
    'Flask==0.8',
    'Flask-Script==0.3.1',
    'Jinja2==2.5.5',
    'Werkzeug==0.8.1',
    'argparse==1.2.1',
    'distribute==0.6.15',
    'wsgiref==0.1.2',
    'decorator==3.3.2',
    'omnijson==0.1.2',
    'gevent'
]

setup(
    name='httpbin',
    version='0.0.5',
    install_requires=deps,
    description='HTTP Request and Response Service.',
    long_description='httpbin.org',
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
    entry_points={
        'console_scripts': [
            'httpbin = httpbin.runner:main',
        ],
    }
)
