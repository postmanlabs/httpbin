FROM python:3.6.7-slim

LABEL name="httpbin"
LABEL version="0.9.2"
LABEL description="A simple HTTP service."
LABEL org.kennethreitz.vendor="Kenneth Reitz"

EXPOSE 8080

ADD . /httpbin

RUN pip3 install --no-cache-dir gunicorn /httpbin

CMD ["gunicorn", "-b", "0.0.0.0:8080", "httpbin:app", "-k", "gevent"]
