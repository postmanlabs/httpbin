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
    os.chdir(_path_to('docs'))
    os.system('make')


def prod():
    """Runs all command on the production instance."""
    global CMD_TEMPLATE

    CMD_TEMPLATE = 'epio run_command {0}'


def deploy():
    """Deploys the application"""

    prod()
    local('epio upload')

