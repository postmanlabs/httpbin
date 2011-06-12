#!/usr/bin/env python
# -*- coding: utf-8 -*-

from flask import Flask
from flaskext.script import Manager, Command

app = Flask(__name__)
# configure your app

manager = Manager(app)


@manager.command
def hello():
    """Hello World!"""
    print r'\o/'


if __name__ == "__main__":
    manager.run()