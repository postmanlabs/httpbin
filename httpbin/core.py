# -*- coding: utf-8 -*-

"""
httpbin.core
~~~~~~~~~~~~

This module provides the core HttpBin experience.
"""

import json

from flask import Flask, request, render_template



app = Flask(__name__)



def to_json(*args, **kwargs):
    data = dict(*args, **kwargs)
    return json.dumps(data)



# ------
# Routes
# ------


@app.route('/')
def view_landing_page():
    return render_template('httpbin.1.html')


@app.route('/headers')
def view_headers():
    return to_json(headers='headers')


@app.route('/user-agent')
def view_user_agent():
    return 'user agent'


@app.route('/get')
def view_get():
    return 'get'



# /headers
# /get
# /post
# /put
# /delete



if __name__ == '__main__':
    app.run()