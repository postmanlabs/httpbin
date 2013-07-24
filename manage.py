#!/usr/bin/env python
# -*- coding: utf-8 -*-

from httpbin import app
from flask.ext.script import Manager, Command


manager = Manager(app)


@manager.command
def hello():
    """Hello World!"""
    print r'\o/'


if __name__ == "__main__":
    manager.run()