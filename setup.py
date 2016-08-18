from setuptools import setup, find_packages
import os
import io

long_description = io.open(
    os.path.join(os.path.dirname(__file__), 'README.rst'), encoding='utf-8').read()

setup(
    name="httpbin",
    version="0.5.0",
    description="HTTP Request and Response Service",
    long_description=long_description,

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
