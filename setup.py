from setuptools import setup, find_packages
import codecs
import os
import re

setup(
    # Note that this requires pandoc on the build host
    setup_requires='setuptools-markdown',

    name="httpbin",
    version="0.2.0",
    description="HTTP Request and Response Service",
    long_description_markdown_filename='README.md',

    # The project URL.
    url='https://github.com/Runscope/httpbin',

    # Author details
    author='Runscope',
    author_email='httpbin@runscope.com',

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
