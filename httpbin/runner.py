# -*- coding: utf-8 -*-

"""
httpbin.runner
~~~~~~~~~~~~~~

This module serves as a command-line runner for httpbin, powered by
gunicorn.

"""

import sys

from gevent.wsgi import WSGIServer
from core import app


def main():
    try:
        port = int(sys.argv[1])
    except (KeyError, ValueError, IndexError):
        port = 5000

    print 'Starting httpbin on port {0}'.format(port)
    http_server = WSGIServer(('', port), app)
    http_server.serve_forever()

if __name__ == '__main__':
    main()
