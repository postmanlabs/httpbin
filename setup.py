from setuptools import setup, find_packages
import codecs
import os
import re

setup(
    name="httpbin",
    version="0.1.1",
    description="HTTP Request and Response Service",

    # The project URL.
    url='https://github.com/kennethreitz/httpbin',

    # Author details
    author='Kenneth Reitz',
    author_email='me@kennethreitz.com',

    # Choose your license
    license='MIT',

    classifiers=[
         'Development Status :: 5 - Production/Stable',
         'Intended Audience :: Developers',
         'Natural Language :: English',
         'License :: OSI Approved :: MIT License',
         'Programming Language :: Python',
         'Programming Language :: Python :: 2.7',
         'Programming Language :: Python :: 3.4',
    ],
    packages=find_packages(),
    include_package_data = True, # include files listed in MANIFEST.in
    install_requires=['Flask','MarkupSafe','decorator','itsdangerous','six'],
)
