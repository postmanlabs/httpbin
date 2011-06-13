#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
from fabric.api import *


CMD_TEMPLATE = '{0}'


def _run(cmd):
    local(CMD_TEMPLATE.format(cmd))


def _path_to(*loc):
    path_tree = __file__.split('/')[:-1]
    path_tree.extend(loc)

    return '/'.join(path_tree)


def docs():
    os.chdir(_path_to('.'))
    os.system('ronn -5 -f README.md --style 80c --pipe > ./httpbin/templates/httpbin.1.html')


def prod():
    """Runs all command on the production instance."""
    global CMD_TEMPLATE

    CMD_TEMPLATE = 'epio run_command {0}'


def push():
    """Deploys the application"""

    # docs()
    prod()
    local('epio upload')

