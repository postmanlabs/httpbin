# -*- coding: utf-8 -*-

"""
httpbin.core
~~~~~~~~~~~~

This module provides the core HttpBin experience.
"""


from flask import Flask
app = Flask(__name__)


@app.route("/")
def hello():
    return "Hello World!"

if __name__ == "__main__":
    app.run()