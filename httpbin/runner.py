# -*- coding: utf-8 -*-

"""
httpbin.runner
~~~~~~~~~~~~~~

This module serves as a command-line runner for httpbin, powered by
gunicorn.

"""

import sys

from gevent.pywsgi import WSGIServer
from werkzeug.exceptions import NotFound
from werkzeug.wsgi import DispatcherMiddleware
from httpbin import app


def main():
    try:
        port = int(sys.argv[1])
    except (KeyError, ValueError, IndexError):
        port = 5000

    try:
        mount = sys.argv[2]
    except IndexError:
        mount = ''

    mounted_app = DispatcherMiddleware(NotFound(), {mount: app})

    print 'Starting httpbin on port {0}'.format(port)
    http_server = WSGIServer(('', port), mounted_app)
    http_server.serve_forever()

if __name__ == '__main__':
    main()
