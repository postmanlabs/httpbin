#!/usr/bin/env python
# -*- coding: utf-8 -*-

from fabric.api import *


CMD_TEMPLATE = '{0}'


def _run(cmd):
    local(CMD_TEMPLATE.format(cmd))


def prod():
    """Runs all command on the production instance."""
    global CMD_TEMPLATE

    CMD_TEMPLATE = 'epio run_command {0}'


def deploy():
    """Deploys the application"""

    prod()
    local('epio upload')

