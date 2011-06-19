#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
from fabric.api import *



CMD_TEMPLATE = '{0}'
EPIO_TEMPLATE = 'epio {0}'


def _run(cmd):
    local(CMD_TEMPLATE.format(cmd))


def _path_to(*loc):
    path_tree = __file__.split('/')[:-1]
    path_tree.extend(loc)

    return '/'.join(path_tree)


def docs():
    os.chdir(_path_to('.'))
    os.system("cat README.md|sed 's/(http:\/\/httpbin.org\//(\//'|ronn -5 -f --style 80c --pipe > ./httpbin/templates/httpbin.1.html")


def epio(cmd):
    """Runs given command on EPIO."""

    c = EPIO_TEMPLATE.format(cmd)

    print c

    os.system(c)



def prod():
    """Runs all command on the production instance."""
    global CMD_TEMPLATE
    global EPIO_TEMPLATE

    CMD_TEMPLATE = 'epio run_command {0} -a httpbin'
    EPIO_TEMPLATE = 'epio {0} -a httpbin '


def stag():
    """Runs all command on the staging instance."""
    global CMD_TEMPLATE
    global EPIO_TEMPLATE

    CMD_TEMPLATE = 'epio run_command {0} -a httpbin-staging'
    EPIO_TEMPLATE = 'epio {0} -a httpbin-staging '


def push():
    """Pushes the application"""

    docs()
    epio('upload')


def stage():
    """Deploys the application."""

    stag()
    push()


def deploy():
    """Deploys the application."""

    prod()
    push()
